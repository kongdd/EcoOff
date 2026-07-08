use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use crate::app::Proc;

#[derive(Default)]
pub struct Rule {
    pub allow_name: HashSet<String>,
    pub allow_parent: HashSet<String>,
    pub deny_name: HashSet<String>,
}

pub struct Config {
    pub scan_interval_secs: u64,
    pub rule: Rule,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan_interval_secs: 60,
            rule: Rule::default(),
        }
    }
}

fn low(s: impl AsRef<str>) -> String {
    s.as_ref().to_ascii_lowercase()
}

pub fn load(path: &Path) -> std::io::Result<Config> {
    let text = fs::read_to_string(path)?;
    let mut cfg = Config::default();
    let mut lines = text.lines();

    while let Some(line) = lines.next() {
        let s = clean(line);
        if s.is_empty() {
            continue;
        }
        let Some((key, val)) = s.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let mut val = val.trim().to_string();
        while val.starts_with('[') && !val.contains(']') {
            let Some(next) = lines.next() else {
                break;
            };
            val.push('\n');
            val.push_str(&clean(next));
        }
        match key {
            "scan_interval_secs" => {
                cfg.scan_interval_secs = val.parse().unwrap_or(cfg.scan_interval_secs);
            }
            "allow" => cfg
                .rule
                .allow_name
                .extend(strings(&val).into_iter().map(low)),
            "allow_parent" => cfg
                .rule
                .allow_parent
                .extend(strings(&val).into_iter().map(low)),
            "deny" => cfg
                .rule
                .deny_name
                .extend(strings(&val).into_iter().map(low)),
            _ => {}
        }
    }
    Ok(cfg)
}

pub fn matched(p: &Proc, ps: &HashMap<u32, Proc>, r: &Rule) -> bool {
    let name = low(&p.name);
    if r.deny_name.contains(&name) {
        return false;
    }
    if r.allow_name.contains(&name) {
        return true;
    }
    has_parent(p, ps, &r.allow_parent)
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

fn clean(line: &str) -> String {
    line.split('#').next().unwrap_or("").trim().to_string()
}

fn strings(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut escape = false;
    for c in s.chars() {
        if escape {
            cur.push(c);
            escape = false;
        } else if c == '\\' && quoted {
            escape = true;
        } else if c == '"' {
            if quoted {
                out.push(cur.clone());
                cur.clear();
            }
            quoted = !quoted;
        } else if quoted {
            cur.push(c);
        }
    }
    out
}
