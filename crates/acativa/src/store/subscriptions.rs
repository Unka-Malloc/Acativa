//! Durable subscription registry for committed workflow transitions.

use anyhow::{Result, anyhow, ensure};
use rusqlite::{OptionalExtension, params};

use crate::routing::{
    ActivationRule, NodeLifecycleState, Subscription, SubscriptionPredicate, SubscriptionRegistry,
    SubscriptionScope,
};

use super::store::{StoreDialect, StrategyStore};

#[derive(Clone, Debug)]
pub struct DurableSubscriptionStore {
    store: StrategyStore,
}

impl DurableSubscriptionStore {
    pub(crate) fn from_store(store: StrategyStore) -> Self {
        Self { store }
    }

    pub fn open(portable_root: &std::path::Path, dialect: &StoreDialect) -> Result<Self> {
        Ok(Self::from_store(StrategyStore::open(
            portable_root,
            dialect,
        )?))
    }

    /// Register is idempotent for the same subscription identity and payload.
    /// A changed predicate or scope must use a new identity so cursor history
    /// cannot silently change meaning.
    pub fn subscribe(&self, subscription: &Subscription) -> Result<bool> {
        validate_subscription(subscription)?;
        let scope_json = serde_json::to_string(&subscription.scope)?;
        let predicate_json = serde_json::to_string(&subscription.predicate)?;
        let activation_json = serde_json::to_string(&subscription.activation_rule)?;
        self.store.with_connection(|connection| {
            let existing: Option<(String, String, String, String, i64, i64, i64)> = connection
                .query_row(
                    "SELECT subscriber_id, scope_json, predicate_json, activation_json,
                            durable_cursor, is_control, active
                     FROM workflow_subscriptions WHERE subscription_id=?1",
                    params![subscription.subscription_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .optional()?;
            if let Some((subscriber, scope, predicate, activation, _cursor, is_control, active)) =
                existing
            {
                ensure!(
                    subscriber == subscription.subscriber_id
                        && scope == scope_json
                        && predicate == predicate_json
                        && activation == activation_json
                        && is_control == i64::from(subscription.is_control)
                        && active == i64::from(subscription.active),
                    "workflow_subscription_conflict"
                );
                return Ok(false);
            }
            connection.execute(
                "INSERT INTO workflow_subscriptions(
                   subscription_id, subscriber_id, scope_json, predicate_json,
                   activation_json, durable_cursor, is_control, active, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    subscription.subscription_id,
                    subscription.subscriber_id,
                    scope_json,
                    predicate_json,
                    activation_json,
                    subscription.durable_cursor as i64,
                    i64::from(subscription.is_control),
                    i64::from(subscription.active),
                    unix_ms(),
                ],
            )?;
            Ok(true)
        })
    }

    pub fn unsubscribe(&self, subscription_id: &str) -> Result<bool> {
        validate_id(subscription_id)?;
        self.store.with_connection(|connection| {
            Ok(connection.execute(
                "DELETE FROM workflow_subscriptions WHERE subscription_id=?1",
                params![subscription_id],
            )? == 1)
        })
    }

    pub fn list(&self) -> Result<Vec<Subscription>> {
        self.store.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT subscription_id, subscriber_id, scope_json, predicate_json,
                        activation_json, durable_cursor, is_control, active
                 FROM workflow_subscriptions ORDER BY subscription_id ASC",
            )?;
            let rows = statement.query_map([], subscription_row)?;
            rows.map(|row| row.map_err(Into::into).and_then(decode_subscription))
                .collect()
        })
    }

    pub fn matching(
        &self,
        scope: &SubscriptionScope,
        predicate: &SubscriptionPredicate,
        target_state: Option<NodeLifecycleState>,
    ) -> Result<Vec<Subscription>> {
        let registry = self.list()?.into_iter().fold(
            SubscriptionRegistry::new(),
            |mut registry, subscription| {
                registry.subscribe(subscription);
                registry
            },
        );
        Ok(registry.match_event(scope, predicate, target_state))
    }

    pub fn advance_cursor(&self, subscription_id: &str, new_cursor: u64) -> Result<bool> {
        validate_id(subscription_id)?;
        self.store.with_connection(|connection| {
            Ok(connection.execute(
                "UPDATE workflow_subscriptions SET durable_cursor=MAX(durable_cursor, ?2)
                 WHERE subscription_id=?1",
                params![subscription_id, new_cursor as i64],
            )? == 1)
        })
    }
}

pub(crate) fn initialize_schema(connection: &rusqlite::Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS workflow_subscriptions(
           subscription_id TEXT PRIMARY KEY,
           subscriber_id TEXT NOT NULL,
           scope_json TEXT NOT NULL,
           predicate_json TEXT NOT NULL,
           activation_json TEXT NOT NULL,
           durable_cursor INTEGER NOT NULL,
           is_control INTEGER NOT NULL,
           active INTEGER NOT NULL,
           created_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS workflow_subscriptions_cursor_idx
           ON workflow_subscriptions(active, durable_cursor);",
    )?;
    Ok(())
}

fn validate_subscription(subscription: &Subscription) -> Result<()> {
    validate_id(&subscription.subscription_id)?;
    validate_id(&subscription.subscriber_id)?;
    ensure!(
        subscription.durable_cursor <= i64::MAX as u64,
        "workflow_subscription_cursor_invalid"
    );
    Ok(())
}

fn validate_id(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty()
            && value == value.trim()
            && value.len() <= 160
            && !value.chars().any(char::is_control),
        "workflow_subscription_id_invalid"
    );
    Ok(())
}

type SubscriptionRow = (String, String, String, String, String, i64, i64, i64);

fn subscription_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SubscriptionRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn decode_subscription(row: SubscriptionRow) -> Result<Subscription> {
    Ok(Subscription {
        subscription_id: row.0,
        subscriber_id: row.1,
        scope: serde_json::from_str::<SubscriptionScope>(&row.2)
            .map_err(|_| anyhow!("workflow_subscription_scope_invalid"))?,
        predicate: serde_json::from_str::<SubscriptionPredicate>(&row.3)
            .map_err(|_| anyhow!("workflow_subscription_predicate_invalid"))?,
        activation_rule: serde_json::from_str::<ActivationRule>(&row.4)
            .map_err(|_| anyhow!("workflow_subscription_activation_invalid"))?,
        durable_cursor: row.5.max(0) as u64,
        is_control: row.6 != 0,
        active: row.7 != 0,
    })
}

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn subscriptions_persist_predicates_and_advance_cursor_monotonically() {
        let root =
            std::env::temp_dir().join(format!("lico-workflow-subscriptions-{}", Uuid::new_v4()));
        let subscription = Subscription {
            subscription_id: "subscription-1".into(),
            subscriber_id: "subscriber-1".into(),
            scope: SubscriptionScope::Graph("graph-1".into()),
            predicate: SubscriptionPredicate::OnAnyTransition,
            activation_rule: ActivationRule::NotifyOnly,
            durable_cursor: 7,
            is_control: false,
            active: true,
        };
        {
            let store = StrategyStore::open(&root, &StoreDialect::generic()).unwrap();
            let subscriptions = store.durable_subscriptions();
            assert!(subscriptions.subscribe(&subscription).unwrap());
            assert!(!subscriptions.subscribe(&subscription).unwrap());
            assert!(subscriptions.advance_cursor("subscription-1", 3).unwrap());
            assert!(subscriptions.advance_cursor("subscription-1", 11).unwrap());
        }

        let store = StrategyStore::open(&root, &StoreDialect::generic()).unwrap();
        let subscriptions = store.durable_subscriptions();
        let mut replay_registration = subscription.clone();
        replay_registration.durable_cursor = 1;
        assert!(!subscriptions.subscribe(&replay_registration).unwrap());
        let listed = subscriptions.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].durable_cursor, 11);
        let matching = subscriptions
            .matching(
                &SubscriptionScope::Node {
                    graph_id: "graph-1".into(),
                    node_id: "node-1".into(),
                },
                &SubscriptionPredicate::OnAnyTransition,
                Some(NodeLifecycleState::Running),
            )
            .unwrap();
        assert_eq!(matching, listed);
        drop(subscriptions);
        drop(store);
        let _ = fs::remove_dir_all(root);
    }
}
