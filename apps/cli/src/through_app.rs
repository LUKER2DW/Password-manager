//! `vault run`, `vault inject` and `vault git-credential`: secrets for programs and scripts,
//! asked of the desktop app while its vault is open, each use approved there
//! (`vault_platform::cli_link`). These never open the vault themselves, so no master password is
//! ever typed into, or kept by, a script.

use std::{
    collections::HashMap,
    io::{BufRead, Read, Write},
    path::PathBuf,
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};
use vault_platform::cli_link::{self, Answer, Reference, Request};
use zeroize::Zeroizing;

/// Asks the app, and turns its refusals into errors that say what to do.
fn ask(request: &Request) -> Result<Answer> {
    let answer = cli_link::ask(request).context(
        "the desktop app isn't running, or its Settings → Security → \"The vault command\" is off",
    )?;
    match answer {
        Answer::Denied => bail!("refused in the app"),
        Answer::Locked => bail!(
            "the vault is locked, or the item waits for the item lock: open it in the app, then \
             try again"
        ),
        Answer::NotFound { what } => bail!("not in the vault: {what}"),
        Answer::Error { detail } => bail!("the app couldn't answer: {detail}"),
        other => Ok(other),
    }
}

/// The values of `refs`, in their order, approved in the app for `purpose`.
fn values(purpose: String, refs: Vec<Reference>) -> Result<Vec<cli_link::Secret>> {
    let count = refs.len();
    match ask(&Request::Get { purpose, refs })? {
        Answer::Values { values } if values.len() == count => Ok(values),
        _ => bail!("the app answered something else"),
    }
}

/// How a command is shown in the app's question: the program's name and its arguments, cut
/// short.
fn shown(program: &str, args: &[String]) -> String {
    let name = std::path::Path::new(program)
        .file_name()
        .map_or_else(|| program.to_owned(), |n| n.to_string_lossy().into_owned());
    let mut text = std::iter::once(name)
        .chain(args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    if text.chars().count() > 120 {
        text = text.chars().take(119).collect::<String>() + "…";
    }
    text
}

/// `vault run [--env NAME=vault://…] -- program args…`: every variable of the environment
/// whose value is a `vault://` reference, and each one given with `--env`, holds the secret
/// instead when the program starts. Returns the program's exit code.
pub fn run(env: Vec<String>, command: Vec<String>) -> Result<i32> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow!("give the program to run after --"))?;
    let mut wanted: Vec<(String, Reference)> = std::env::vars_os()
        .filter_map(|(name, value)| {
            let reference = Reference::parse(value.to_str()?)?;
            Some((name.to_str()?.to_owned(), reference))
        })
        .collect();
    for pair in env {
        let (name, value) = pair
            .split_once('=')
            .ok_or_else(|| anyhow!("--env {pair}: write it as NAME=vault://item/field"))?;
        let reference = Reference::parse(value)
            .ok_or_else(|| anyhow!("--env {name}: {value} isn't a vault://item/field reference"))?;
        wanted.retain(|(other, _)| other != name);
        wanted.push((name.to_owned(), reference));
    }
    if wanted.is_empty() {
        bail!("no vault://item/field reference in the environment or in --env");
    }
    let (names, refs): (Vec<String>, Vec<Reference>) = wanted.into_iter().unzip();
    let secrets = values(format!("run {}", shown(program, args)), refs)?;
    let mut child = Command::new(program);
    child.args(args);
    for (name, secret) in names.iter().zip(&secrets) {
        child.env(name, secret.as_str());
    }
    let status = child
        .status()
        .with_context(|| format!("starting {program}"))?;
    Ok(status.code().unwrap_or(1))
}

/// Where `{{ vault://item/field }}` is in a template: each place's start and end (the braces
/// included) and its reference. Other `{{ … }}` are left alone (another tool's templates).
pub fn find_references(template: &str) -> Result<Vec<(usize, usize, Reference)>> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(open) = template[from..].find("{{").map(|at| from + at) {
        let Some(close) = template[open + 2..].find("}}").map(|at| open + 2 + at) else {
            break;
        };
        let inside = template[open + 2..close].trim();
        if inside.starts_with("vault://") {
            let reference = Reference::parse(inside)
                .ok_or_else(|| anyhow!("{inside}: not a vault://item/field reference"))?;
            found.push((open, close + 2, reference));
        }
        from = close + 2;
    }
    Ok(found)
}

/// `template` with each place [`find_references`] found replaced by its value.
pub fn fill(
    template: &str,
    places: &[(usize, usize, Reference)],
    values: &[cli_link::Secret],
) -> Zeroizing<String> {
    let extra: usize = values.iter().map(|v| v.as_str().len()).sum();
    let mut out = Zeroizing::new(String::with_capacity(template.len() + extra));
    let mut at = 0;
    for ((start, end, _), value) in places.iter().zip(values) {
        out.push_str(&template[at..*start]);
        out.push_str(value.as_str());
        at = *end;
    }
    out.push_str(&template[at..]);
    out
}

/// `vault inject [--in FILE] [--out FILE]`: the template (standard input by default) with its
/// `{{ vault://item/field }}` filled, written out (standard output by default).
pub fn inject(input: Option<PathBuf>, output: Option<PathBuf>) -> Result<()> {
    let template = match &input {
        Some(path) => {
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?
        }
        None => {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text)?;
            text
        }
    };
    let places = find_references(&template)?;
    let filled = if places.is_empty() {
        Zeroizing::new(template.clone())
    } else {
        // Each reference asked once, however many times the template names it.
        let mut unique: Vec<Reference> = Vec::new();
        for (_, _, reference) in &places {
            if !unique.contains(reference) {
                unique.push(reference.clone());
            }
        }
        let what = input
            .as_ref()
            .and_then(|path| path.file_name())
            .map_or_else(
                || "a template".to_owned(),
                |n| n.to_string_lossy().into_owned(),
            );
        let got = values(format!("fill {what}"), unique.clone())?;
        let ordered: Vec<cli_link::Secret> = places
            .iter()
            .map(|(_, _, reference)| {
                let at = unique.iter().position(|u| u == reference).unwrap_or(0);
                cli_link::Secret::new(got[at].as_str())
            })
            .collect();
        fill(&template, &places, &ordered)
    };
    match output {
        Some(path) => std::fs::write(&path, filled.as_bytes())
            .with_context(|| format!("writing {}", path.display()))?,
        None => std::io::stdout().write_all(filled.as_bytes())?,
    }
    Ok(())
}

/// Reads git's credential description (`key=value` lines up to a blank line).
pub fn read_description(input: impl BufRead) -> Result<HashMap<String, String>> {
    let mut fields = HashMap::new();
    for line in input.lines() {
        let line = line?;
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once('=') {
            fields.insert(key.to_owned(), value.to_owned());
        }
    }
    Ok(fields)
}

/// `vault git-credential get|store|erase`: git's credential helper (`git config --global
/// credential.helper "vault git-credential"`). `get` answers with the login saved for the site
/// git asks about (https only), approved in the app; nothing found, refused or locked, it
/// answers nothing and git asks as it would without it. `store` and `erase` change nothing:
/// the vault is where a login is saved or changed.
pub fn git_credential(action: &str) -> Result<()> {
    let fields = read_description(std::io::stdin().lock())?;
    if action != "get" {
        return Ok(());
    }
    let (Some(protocol), Some(host)) = (fields.get("protocol"), fields.get("host")) else {
        return Ok(());
    };
    if protocol != "https" {
        return Ok(());
    }
    let request = Request::Login {
        purpose: format!("git, for {host}"),
        url: format!("https://{host}"),
        username: fields.get("username").cloned(),
    };
    match ask(&request) {
        Ok(Answer::Login { username, password }) => {
            let mut out = Zeroizing::new(format!(
                "username={}\npassword={}\n",
                username.as_str(),
                password.as_str()
            ));
            std::io::stdout().write_all(out.as_bytes())?;
            zeroize::Zeroize::zeroize(&mut *out);
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(err) => {
            // Git goes on without it (it asks in the terminal); the reason goes to stderr.
            eprintln!("vault: {err:#}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_are_filled_where_they_name_the_vault() {
        let template = "user={{ vault://Mail/username }}\npass={{vault://Mail/password}}\nkeep={{ other }}\nagain={{ vault://Mail/username }}\n";
        let places = find_references(template).unwrap();
        assert_eq!(places.len(), 3);
        assert_eq!(
            places[0].2,
            Reference::parse("vault://Mail/username").unwrap()
        );
        assert_eq!(places[1].2.field, "password");
        let values = ["me", "pw", "me"].map(cli_link::Secret::new);
        assert_eq!(
            fill(template, &places, &values).as_str(),
            "user=me\npass=pw\nkeep={{ other }}\nagain=me\n"
        );
        assert!(find_references("{{ vault://no-field }}").is_err());
        assert!(find_references("nothing {{ here").unwrap().is_empty());
    }

    #[test]
    fn git_descriptions_are_read_up_to_the_blank_line() {
        let fields = read_description(
            "protocol=https\nhost=example.com\nusername=me\n\nignored=1\n".as_bytes(),
        )
        .unwrap();
        assert_eq!(fields["protocol"], "https");
        assert_eq!(fields["host"], "example.com");
        assert_eq!(fields["username"], "me");
        assert!(!fields.contains_key("ignored"));
    }

    #[test]
    fn commands_are_shown_short() {
        assert_eq!(
            shown(r"C:\tools\cargo.exe", &["publish".into()]),
            "cargo.exe publish"
        );
        let long: Vec<String> = (0..100).map(|i| i.to_string()).collect();
        assert!(shown("x", &long).chars().count() <= 120);
    }
}
