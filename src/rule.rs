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

fn low(s: impl AsRef<str>) -> String {
    s.as_ref().to_ascii_lowercase()
}

pub fn load(path: &Path) -> std::io::Result<Rule> {
    let mut r = Rule::default();
    for line in fs::read_to_string(path)?.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        if let Some(x) = s.strip_prefix("+parent:") {
            r.allow_parent.insert(low(x));
        } else if let Some(x) = s.strip_prefix('+') {
            r.allow_name.insert(low(x));
        } else if let Some(x) = s.strip_prefix('-') {
            r.deny_name.insert(low(x));
        }
    }
    Ok(r)
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
