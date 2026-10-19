//! Read-only comparison against a schema constructed by its actual owner.
//!
//! SQLite's PRAGMAs omit CHECK expressions, conflict clauses, FK deferral and
//! partial predicates. Compare tokenized declarations as well as SQLite's own
//! column metadata. This is deliberately not a SQL equivalence prover: owners
//! admit their producer layouts, including explicitly named producer variants.
//! Column order, identifier quoting, comments and SQL keyword case are immaterial;
//! string literals and every constraint remain significant.

use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension};
use std::collections::BTreeMap;

pub fn tokens(sql: &str) -> Result<Vec<String>> {
    let mut input = sql.chars().peekable();
    let mut out = Vec::new();
    while let Some(ch) = input.next() {
        if ch.is_whitespace() {
            continue;
        }
        if ch == '-' && input.peek() == Some(&'-') {
            input.next();
            for ch in input.by_ref() {
                if ch == '\n' {
                    break;
                }
            }
            continue;
        }
        if ch == '/' && input.peek() == Some(&'*') {
            input.next();
            let mut closed = false;
            while let Some(ch) = input.next() {
                if ch == '*' && input.peek() == Some(&'/') {
                    input.next();
                    closed = true;
                    break;
                }
            }
            ensure!(closed, "unsupported_state_shape");
            continue;
        }
        if matches!(ch, '\'' | '"' | '`' | '[') {
            let end = if ch == '[' { ']' } else { ch };
            let mut value = String::new();
            let mut closed = false;
            while let Some(next) = input.next() {
                if next == end {
                    if end != ']' && input.peek() == Some(&end) {
                        input.next();
                        value.push(end);
                        continue;
                    }
                    closed = true;
                    break;
                }
                value.push(next);
            }
            ensure!(closed, "unsupported_state_shape");
            out.push(if ch == '\'' {
                format!("'{}'", value.replace('\'', "''"))
            } else {
                value.to_ascii_lowercase()
            });
        } else if ch.is_alphanumeric() || ch == '_' {
            let mut word = ch.to_string();
            while input
                .peek()
                .is_some_and(|ch| ch.is_alphanumeric() || *ch == '_')
            {
                word.push(input.next().unwrap());
            }
            out.push(word.to_ascii_lowercase());
        } else {
            out.push(ch.to_string());
        }
    }
    while out.last().is_some_and(|token| token == ";") {
        out.pop();
    }
    Ok(out)
}

fn declaration(sql: &str) -> Result<Vec<Vec<String>>> {
    let tokens = tokens(sql)?;
    if let Some(using) = tokens.iter().position(|token| token == "using") {
        return Ok(vec![tokens[using..].to_vec()]);
    }
    let begin = tokens
        .iter()
        .position(|token| token == "(")
        .ok_or_else(|| anyhow::anyhow!("unsupported_state_shape"))?;
    let mut result = Vec::new();
    let mut depth = 1;
    let mut start = begin + 1;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token.as_str() {
            "(" => depth += 1,
            ")" => depth -= 1,
            "," if depth == 1 => {
                result.push(tokens[start..index].to_vec());
                start = index + 1;
            }
            _ => {}
        }
        if depth == 0 {
            result.push(tokens[start..index].to_vec());
            result.sort();
            // STRICT / WITHOUT ROWID are observable storage and write semantics.
            result.push(tokens[index + 1..].to_vec());
            return Ok(result);
        }
    }
    anyhow::bail!("unsupported_state_shape")
}

fn table_sql(connection: &Connection, name: &str) -> Result<Option<String>> {
    Ok(connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
            [name],
            |row| row.get(0),
        )
        .optional()?)
}

type ColumnFacts = BTreeMap<String, (String, bool, Option<String>, i64, i64)>;

fn columns(connection: &Connection, name: &str) -> Result<ColumnFacts> {
    Ok(connection
        .prepare("SELECT name,type,\"notnull\",dflt_value,pk,hidden FROM pragma_table_xinfo(?1)")?
        .query_map([name], |row| {
            Ok((
                row.get(0)?,
                (
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?)
}

fn definitions(
    connection: &Connection,
    table: &str,
    kind: &str,
) -> Result<BTreeMap<String, Vec<String>>> {
    let rows = connection
        .prepare(
            "SELECT name,sql FROM sqlite_schema WHERE type=?1 AND tbl_name=?2 AND sql IS NOT NULL",
        )?
        .query_map([kind, table], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|(name, sql)| {
            let mut tokens = tokens(&sql)?;
            // IF NOT EXISTS is not part of the resulting object's semantics.
            if let Some(index) = tokens.windows(3).position(|t| t == ["if", "not", "exists"]) {
                tokens.drain(index..index + 3);
            }
            Ok((name, tokens))
        })
        .collect()
}

/// A physical column difference emitted by an actual supported producer.
#[derive(Clone, Copy)]
pub enum ColumnVariant<'a> {
    Nullable(&'a str),
    MissingZeroDefault(&'a str),
}

/// Compare one required table. A column exception identifies an actual
/// producer variant, not permission to weaken other columns. Absent optional
/// tables are handled by the caller, which owns whether startup creates them.
pub fn validate_table(
    source: &Connection,
    reference: &Connection,
    name: &str,
    variant: Option<ColumnVariant<'_>>,
) -> Result<()> {
    let actual_sql =
        table_sql(source, name)?.ok_or_else(|| anyhow::anyhow!("unsupported_state_shape"))?;
    let expected_sql =
        table_sql(reference, name)?.ok_or_else(|| anyhow::anyhow!("unsupported_state_shape"))?;
    let mut expected = declaration(&expected_sql)?;
    let actual = declaration(&actual_sql)?;
    let actual_columns = columns(source, name)?;
    let mut expected_columns = columns(reference, name)?;
    if let Some(ColumnVariant::Nullable(column)) = variant
        && actual_columns.get(column).is_some_and(|value| !value.1)
    {
        if let Some(value) = expected_columns.get_mut(column) {
            value.1 = false;
        }
        for entry in &mut expected {
            if entry.first().is_some_and(|name| name == column)
                && let Some(index) = entry.windows(2).position(|t| t == ["not", "null"])
            {
                entry.drain(index..index + 2);
            }
        }
    }
    if let Some(ColumnVariant::MissingZeroDefault(column)) = variant
        && actual_columns
            .get(column)
            .is_some_and(|value| value.2.is_none())
    {
        if let Some(value) = expected_columns.get_mut(column) {
            ensure!(
                value.2.as_deref().map(tokens).transpose()? == Some(vec!["0".into()]),
                "unsupported_state_shape"
            );
            value.2 = None;
        }
        for entry in &mut expected {
            if entry.first().is_some_and(|name| name == column)
                && let Some(index) = entry.windows(2).position(|t| t == ["default", "0"])
            {
                entry.drain(index..index + 2);
            }
        }
    }
    // Token declarations also catch defaults, CHECK, FK actions/deferral,
    // collation, generated columns, conflict algorithms and extra columns.
    ensure!(actual == expected, "unsupported_state_shape");
    ensure!(
        actual_columns.len() == expected_columns.len(),
        "unsupported_state_shape"
    );
    for (name, (kind, required, default, pk, hidden)) in expected_columns {
        let observed = actual_columns
            .get(&name)
            .ok_or_else(|| anyhow::anyhow!("unsupported_state_shape"))?;
        ensure!(
            observed.0.eq_ignore_ascii_case(&kind)
                && observed.1 == required
                && observed.3 == pk
                && observed.4 == hidden,
            "unsupported_state_shape"
        );
        ensure!(
            observed.2.as_deref().map(tokens).transpose()?
                == default.as_deref().map(tokens).transpose()?,
            "unsupported_state_shape"
        );
    }
    ensure!(
        definitions(source, name, "index")? == definitions(reference, name, "index")?,
        "unsupported_state_shape"
    );
    ensure!(
        definitions(source, name, "trigger")? == definitions(reference, name, "trigger")?,
        "unsupported_state_shape"
    );
    // Relationships declared by another table belong to that table. SQLite
    // enforces them on the affected operation; their presence does not make
    // this owner's required layout unusable for initialization or reads.
    Ok(())
}

/// Tables defined by the owner, excluding SQLite's virtual-table shadow tables.
pub fn tables(connection: &Connection) -> Result<Vec<String>> {
    Ok(connection.prepare("SELECT name FROM pragma_table_list WHERE schema='main' AND type IN ('table','virtual') AND name NOT LIKE 'sqlite_%' ORDER BY name")?
        .query_map([], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_owner_trigger_is_admitted_but_changed_or_extra_effects_are_refused() {
        let schema = "CREATE TABLE item(id TEXT PRIMARY KEY, revision INTEGER NOT NULL DEFAULT 0, value TEXT);
            CREATE TRIGGER owner_revision AFTER UPDATE OF value ON item
            BEGIN UPDATE item SET revision=revision+1 WHERE id=NEW.id; END;";
        let reference = Connection::open_in_memory().unwrap();
        reference.execute_batch(schema).unwrap();
        let source = Connection::open_in_memory().unwrap();
        source.execute_batch(schema).unwrap();
        validate_table(&source, &reference, "item", None).unwrap();
        source.execute_batch("DROP TRIGGER owner_revision; CREATE TRIGGER owner_revision AFTER UPDATE OF value ON item BEGIN DELETE FROM item WHERE id=NEW.id; END;").unwrap();
        assert!(validate_table(&source, &reference, "item", None).is_err());
        source
            .execute_batch("DROP TRIGGER owner_revision;")
            .unwrap();
        assert!(validate_table(&source, &reference, "item", None).is_err());
        source.execute_batch("CREATE TRIGGER owner_revision AFTER UPDATE OF value ON item BEGIN UPDATE item SET revision=revision+1 WHERE id=NEW.id; END;").unwrap();
        validate_table(&source, &reference, "item", None).unwrap();
        source.execute_batch("CREATE TRIGGER foreign_effect BEFORE INSERT ON item BEGIN SELECT RAISE(ABORT, 'blocked'); END;").unwrap();
        assert!(validate_table(&source, &reference, "item", None).is_err());
    }

    #[test]
    fn formatting_and_column_order_do_not_change_the_contract() {
        let reference = Connection::open_in_memory().unwrap();
        reference.execute_batch("CREATE TABLE sample(id TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT 'Keep Case' CHECK(value != 'DROP')); CREATE INDEX sample_value ON sample(value);").unwrap();
        let source = Connection::open_in_memory().unwrap();
        source.execute_batch("create table \"sample\"(value text not null default 'Keep Case' check(value != 'DROP'), /* unchanged */ \"id\" text primary key); create index if not exists sample_value on sample(value);").unwrap();
        validate_table(&source, &reference, "sample", None).unwrap();
        assert_ne!(
            tokens("'Keep Case'").unwrap(),
            tokens("'keep case'").unwrap()
        );
        assert_ne!(tokens("'a b'").unwrap(), tokens("'ab'").unwrap());
    }

    #[test]
    fn nullable_exception_is_bound_to_one_producer_column() {
        let reference = Connection::open_in_memory().unwrap();
        reference.execute_batch("CREATE TABLE sample(id TEXT PRIMARY KEY, terminal INTEGER NOT NULL, value TEXT NOT NULL);").unwrap();
        let source = Connection::open_in_memory().unwrap();
        source
            .execute_batch(
                "CREATE TABLE sample(id TEXT PRIMARY KEY, terminal INTEGER, value TEXT NOT NULL);",
            )
            .unwrap();
        assert!(validate_table(&source, &reference, "sample", None).is_err());
        validate_table(
            &source,
            &reference,
            "sample",
            Some(ColumnVariant::Nullable("terminal")),
        )
        .unwrap();
        source.execute_batch("DROP TABLE sample; CREATE TABLE sample(id TEXT PRIMARY KEY, terminal INTEGER, value TEXT);").unwrap();
        assert!(
            validate_table(
                &source,
                &reference,
                "sample",
                Some(ColumnVariant::Nullable("terminal"))
            )
            .is_err()
        );
    }

    #[test]
    fn unowned_relations_do_not_prevent_owner_admission() {
        let reference = Connection::open_in_memory().unwrap();
        reference
            .execute_batch("CREATE TABLE sample(id TEXT PRIMARY KEY);")
            .unwrap();
        let source = Connection::open_in_memory().unwrap();
        source
            .execute_batch(
                "CREATE TABLE sample(id TEXT PRIMARY KEY); CREATE TABLE canary(value TEXT);",
            )
            .unwrap();
        validate_table(&source, &reference, "sample", None).unwrap();
        source
            .execute_batch("CREATE TABLE child(id TEXT REFERENCES sample(id) ON DELETE RESTRICT);")
            .unwrap();
        validate_table(&source, &reference, "sample", None).unwrap();
        source.execute_batch("PRAGMA foreign_keys=ON; INSERT INTO sample VALUES ('kept'); INSERT INTO child VALUES ('kept');").unwrap();
        assert!(
            source
                .execute("DELETE FROM sample WHERE id='kept'", [])
                .is_err()
        );
        assert_eq!(
            source
                .query_row("SELECT count(*) FROM child", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
