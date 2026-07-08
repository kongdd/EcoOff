use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use sysinfo::Pid;

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

pub fn pname(p: &sysinfo::Process) -> String {
    p.name().to_string_lossy().to_string()
}

pub fn matched(
    pid: Pid,
    p: &sysinfo::Process,
    ps: &HashMap<Pid, &sysinfo::Process>,
    r: &Rule,
) -> bool {
    let name = low(pname(p));

    if r.deny_name.contains(&name) {
        return false;
    }

    if r.allow_name.contains(&name) {
        return true;
    }

    has_parent(pid, ps, &r.allow_parent)
}

fn has_parent(pid: Pid, ps: &HashMap<Pid, &sysinfo::Process>, names: &HashSet<String>) -> bool {
    let mut cur = pid;

    for _ in 0..32 {
        let Some(p) = ps.get(&cur) else {
            return false;
        };
        let Some(ppid) = p.parent() else {
            return false;
        };
        let Some(parent) = ps.get(&ppid) else {
            return false;
        };

        if names.contains(&low(pname(parent))) {
            return true;
        }

        cur = ppid;
    }

    false
}
