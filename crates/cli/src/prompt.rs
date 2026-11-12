//! Reading secrets and confirmations from the terminal (or from stdin in script mode).

use std::{
    collections::VecDeque,
    io::{self, BufRead, Write},
};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

/// Source of user input. In script mode (`--password-stdin`), every prompt consumes the next
/// line of standard input instead of asking interactively.
pub struct Prompter {
    script_lines: Option<VecDeque<Zeroizing<String>>>,
}

impl Prompter {
    pub fn new(script_mode: bool) -> Result<Self> {
        let script_lines = if script_mode {
            let mut lines = VecDeque::new();
            for line in io::stdin().lock().lines() {
                lines.push_back(Zeroizing::new(line.context("reading stdin")?));
            }
            Some(lines)
        } else {
            None
        };
        Ok(Self { script_lines })
    }

    fn next_script_line(&mut self, label: &str) -> Option<Result<Zeroizing<String>>> {
        let lines = self.script_lines.as_mut()?;
        Some(
            lines
                .pop_front()
                .with_context(|| format!("stdin has no line for: {label}")),
        )
    }

    /// Hidden input (no echo).
    pub fn secret(&mut self, label: &str) -> Result<Zeroizing<String>> {
        if let Some(line) = self.next_script_line(label) {
            return line;
        }
        let value = rpassword::prompt_password(format!("{label}: "))
            .context("reading from the terminal")?;
        Ok(Zeroizing::new(value))
    }

    /// Hidden input typed twice; both entries must match.
    pub fn new_secret(&mut self, label: &str) -> Result<Zeroizing<String>> {
        let first = self.secret(label)?;
        if self.script_lines.is_some() {
            return Ok(first);
        }
        let second = self.secret(&format!("{label} (again)"))?;
        if *first != *second {
            bail!("the two entries do not match");
        }
        Ok(first)
    }

    /// Visible input.
    pub fn line(&mut self, label: &str) -> Result<String> {
        if let Some(line) = self.next_script_line(label) {
            return line.map(|l| l.to_string());
        }
        print!("{label}: ");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().lock().read_line(&mut answer)?;
        Ok(answer.trim_end_matches(['\r', '\n']).to_owned())
    }
}
