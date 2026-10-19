//! Display typography is independent from model identity and availability.

/// Format both catalog names and unresolved native IDs in one Rust-owned
/// projection. Formatting never establishes an alias or a canonical model.
pub fn model_display_name(raw: &str) -> String {
    let mut label = raw.trim();
    while let Some((prefix, rest)) = label.split_once('/') {
        if prefix.chars().any(char::is_whitespace) || rest.trim().is_empty() {
            break;
        }
        label = rest.trim();
    }
    if let Some((prefix, rest)) = label.split_once(':')
        && !prefix
            .chars()
            .any(|c| c.is_whitespace() || c.is_ascii_digit())
        && rest.contains(['-', '_'])
    {
        label = rest.trim();
    }
    let spaced = label.replace(['-', '_'], " ");
    let mut words = spaced.split_whitespace().peekable();
    let mut display = Vec::new();
    let mut found_version = false;
    while let Some(word) = words.next() {
        let mut word = word.to_owned();
        if !found_version && word.chars().any(|c| c.is_ascii_digit()) {
            found_version = true;
            let numeric = word
                .strip_prefix('v')
                .or_else(|| word.strip_prefix('V'))
                .unwrap_or(&word);
            if version_component(numeric) {
                while let Some(next) = words.peek().filter(|next| version_component(next)) {
                    word.push('.');
                    word.push_str(next);
                    words.next();
                }
            }
        }
        display.push(display_word(&word));
    }
    if display.len() > 1 && display.last().is_some_and(|word| word == "Default") {
        display.pop();
    }
    if let Some(index) = display.windows(2).position(|words| {
        words[0] == "GPT" && words[1].chars().next().is_some_and(|c| c.is_ascii_digit())
    }) {
        let version = display.remove(index + 1);
        display[index].push('-');
        display[index].push_str(&version);
    }
    display.join(" ")
}

fn version_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2
        && value.bytes().all(|c| c.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
}

fn display_word(word: &str) -> String {
    let lower = word.to_lowercase();
    let brand = match lower.as_str() {
        "gpt" => Some("GPT"),
        "deepseek" => Some("DeepSeek"),
        "openai" => Some("OpenAI"),
        "chatgpt" => Some("ChatGPT"),
        "minimax" => Some("MiniMax"),
        "xai" => Some("xAI"),
        "glm" => Some("GLM"),
        "ai" => Some("AI"),
        "api" => Some("API"),
        "oss" => Some("OSS"),
        "moe" => Some("MoE"),
        _ => None,
    };
    if let Some(brand) = brand {
        return brand.to_owned();
    }
    // Keep deliberate catalog casing such as QwQ, CodeGeeX, and LFM2.
    // Lowercase native slugs still receive the default title treatment.
    if word.chars().skip(1).any(char::is_uppercase) {
        return word.to_owned();
    }
    let numeric = word.trim_matches(['(', ')', '[', ']']);
    if numeric.chars().next().is_some_and(|c| c.is_ascii_digit())
        && numeric
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'k' | 'K' | 'm' | 'M' | 'b' | 'B'))
    {
        return word.to_ascii_uppercase();
    }
    let Some((offset, letter)) = lower
        .char_indices()
        .find(|(_, letter)| letter.is_alphabetic())
    else {
        return lower;
    };
    format!(
        "{}{}{}",
        &lower[..offset],
        letter.to_uppercase(),
        &lower[offset + letter.len_utf8()..]
    )
}
