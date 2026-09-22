use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::app::Proc;

#[derive(Clone, Default)]
pub struct Rule {
    pub allow_name: HashSet<String>,
    pub allow_parent: HashSet<String>,
    pub deny_name: HashSet<String>,
}

#[derive(Clone)]
pub struct Config {
    pub scan_interval_secs: u64,
    pub rule: Rule,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct EditableConfig {
    pub scan_interval_secs: u64,
    pub allow: Vec<String>,
    pub allow_parent: Vec<String>,
    pub deny: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan_interval_secs: 60,
            rule: Rule::default(),
        }
    }
}

impl From<&Config> for EditableConfig {
    fn from(config: &Config) -> Self {
        fn sorted(items: &HashSet<String>) -> Vec<String> {
            let mut items = items.iter().cloned().collect::<Vec<_>>();
            items.sort_unstable();
            items
        }
        Self {
            scan_interval_secs: config.scan_interval_secs,
            allow: sorted(&config.rule.allow_name),
            allow_parent: sorted(&config.rule.allow_parent),
            deny: sorted(&config.rule.deny_name),
        }
    }
}

fn low(s: impl AsRef<str>) -> String {
    s.as_ref().to_ascii_lowercase()
}

pub fn load(path: &Path) -> io::Result<Config> {
    Ok(parse(&fs::read_to_string(path)?))
}

pub fn save(path: &Path, mut config: EditableConfig) -> io::Result<()> {
    if !(1..=3600).contains(&config.scan_interval_secs) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "扫描间隔须为 1–3600 秒",
        ));
    }
    config.allow = valid_names(config.allow)?;
    config.allow_parent = valid_names(config.allow_parent)?;
    config.deny = valid_names(config.deny)?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(path, format_config(&config))
}

pub fn matched(p: &Proc, ps: &HashMap<u32, Proc>, rule: &Rule) -> bool {
    let name = low(&p.name);
    if rule.deny_name.contains(&name) {
        return false;
    }
    if rule.allow_name.contains(&name) {
        return true;
    }
    has_parent(p, ps, &rule.allow_parent)
}

fn parse(text: &str) -> Config {
    let mut config = Config::default();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let s = clean(line);
        if s.is_empty() {
            continue;
        }
        let Some((key, value)) = s.split_once('=') else {
            continue;
        };
        let mut value = value.trim().to_string();
        while value.starts_with('[') && !value.contains(']') {
            let Some(next) = lines.next() else {
                break;
            };
            value.push('\n');
            value.push_str(&clean(next));
        }
        match key.trim() {
            "scan_interval_secs" => {
                if let Ok(value) = value.parse::<u64>()
                    && (1..=3600).contains(&value)
                {
                    config.scan_interval_secs = value;
                }
            }
            "allow" => config
                .rule
                .allow_name
                .extend(strings(&value).into_iter().map(low)),
            "allow_parent" => config
                .rule
                .allow_parent
                .extend(strings(&value).into_iter().map(low)),
            "deny" => config
                .rule
                .deny_name
                .extend(strings(&value).into_iter().map(low)),
            _ => {}
        }
    }
    config
}

fn has_parent(p: &Proc, ps: &HashMap<u32, Proc>, names: &HashSet<String>) -> bool {
    let mut parent = p.parent;
    for _ in 0..32 {
        let Some(p) = ps.get(&parent) else {
            return false;
        };
        if names.contains(&low(&p.name)) {
            return true;
        }
        parent = p.parent;
    }
    false
}

fn valid_names(names: Vec<String>) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for name in names {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        if name.chars().any(char::is_control) || name.contains(['"', '\\']) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("无效进程名：{name}"),
            ));
        }
        if seen.insert(low(name)) {
            out.push(name.to_string());
        }
    }
    Ok(out)
}

fn format_config(config: &EditableConfig) -> String {
    fn list(name: &str, items: &[String]) -> String {
        if items.is_empty() {
            return format!("{name} = []\n");
        }
        let items = items
            .iter()
            .map(|item| format!("  \"{item}\","))
            .collect::<Vec<_>>()
            .join("\n");
        format!("{name} = [\n{items}\n]\n")
    }

    format!(
        "scan_interval_secs = {}\n\n{}\n{}\n{}",
        config.scan_interval_secs,
        list("allow", &config.allow),
        list("allow_parent", &config.allow_parent),
        list("deny", &config.deny)
    )
}

fn clean(line: &str) -> String {
    line.split('#').next().unwrap_or("").trim().to_string()
}

fn strings(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escape = false;
    for c in s.chars() {
        if escape {
            current.push(c);
            escape = false;
        } else if c == '\\' && quoted {
            escape = true;
        } else if c == '"' {
            if quoted {
                out.push(current.clone());
                current.clear();
            }
            quoted = !quoted;
        } else if quoted {
            current.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trip() {
        let input = EditableConfig {
            scan_interval_secs: 12,
            allow: vec!["Code.exe".into(), "code.exe".into()],
            allow_parent: vec!["orca.exe".into()],
            deny: vec!["System".into()],
        };
        let text = format_config(&input);
        let config = parse(&text);
        assert_eq!(config.scan_interval_secs, 12);
        assert!(config.rule.allow_name.contains("code.exe"));
        assert!(config.rule.allow_parent.contains("orca.exe"));
        assert!(config.rule.deny_name.contains("system"));
    }
}
