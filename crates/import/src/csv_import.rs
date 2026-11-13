//! CSV exports (Chrome, Edge, Firefox, Bitwarden CSV, and similar) with header detection.

use vault_core::{CustomField, ItemData, ItemKind};

use crate::{ImportError, ImportReport, host_of, non_empty};

/// Column name aliases (compared case-insensitively, ignoring spaces and underscores).
const TITLE: &[&str] = &["name", "title", "account"];
const URL: &[&str] = &["url", "loginuri", "website", "uri", "address"];
const USERNAME: &[&str] = &["username", "loginusername", "login", "user", "email"];
const PASSWORD: &[&str] = &["password", "loginpassword"];
const NOTES: &[&str] = &["note", "notes", "extra", "comments", "comment"];
const TOTP: &[&str] = &["totp", "logintotp", "otpauth", "otp"];
const FAVORITE: &[&str] = &["favorite", "fav"];
const KIND: &[&str] = &["type"];
const FIELDS: &[&str] = &["fields"];
/// Bitwarden CSV "folder", LastPass "grouping".
const FOLDER: &[&str] = &["folder", "grouping", "group"];
/// Firefox: milliseconds since the Unix epoch.
const CREATED_MS: &[&str] = &["timecreated"];
const CHANGED_MS: &[&str] = &["timepasswordchanged"];

struct Columns {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
    favorite: Option<usize>,
    kind: Option<usize>,
    fields: Option<usize>,
    folder: Option<usize>,
    created_ms: Option<usize>,
    changed_ms: Option<usize>,
}

impl Columns {
    fn from_headers(headers: &csv::StringRecord) -> Self {
        let normalized: Vec<String> = headers
            .iter()
            .map(|h| h.trim().to_lowercase().replace([' ', '_', '-'], ""))
            .collect();
        let find = |aliases: &[&str]| {
            normalized
                .iter()
                .position(|h| aliases.contains(&h.as_str()))
        };
        Self {
            title: find(TITLE),
            url: find(URL),
            username: find(USERNAME),
            password: find(PASSWORD),
            notes: find(NOTES),
            totp: find(TOTP),
            favorite: find(FAVORITE),
            kind: find(KIND),
            fields: find(FIELDS),
            folder: find(FOLDER),
            created_ms: find(CREATED_MS),
            changed_ms: find(CHANGED_MS),
        }
    }

    fn is_usable(&self) -> bool {
        self.password.is_some() || self.username.is_some() || self.url.is_some()
    }
}

/// Imports a CSV export. The first row must be a header.
pub fn import_csv(bytes: &[u8]) -> Result<ImportReport, ImportError> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(bytes);
    let columns = Columns::from_headers(reader.headers()?);
    if !columns.is_usable() {
        return Err(ImportError::UnknownCsvLayout);
    }

    let mut report = ImportReport::default();
    for (row_index, record) in reader.records().enumerate() {
        let record = record?;
        let get = |column: Option<usize>| {
            column
                .and_then(|i| record.get(i))
                .map(str::to_owned)
                .and_then(|v| non_empty(Some(v)))
        };

        let url = get(columns.url);
        let username = get(columns.username);
        let password = get(columns.password);
        let notes = get(columns.notes);
        if url.is_none() && username.is_none() && password.is_none() && notes.is_none() {
            report
                .warnings
                .push(format!("row {}: empty, skipped", row_index + 2));
            continue;
        }

        let kind = match get(columns.kind)
            .as_deref()
            .map(str::to_lowercase)
            .as_deref()
        {
            Some("note" | "securenote") => ItemKind::SecureNote,
            Some("card") => ItemKind::Card,
            _ => ItemKind::Login,
        };
        let title = get(columns.title)
            .or_else(|| url.as_deref().and_then(host_of))
            .unwrap_or_else(|| "Untitled".into());

        let mut item = ItemData::new(kind, &title);
        item.username = username.unwrap_or_default();
        item.password = password.unwrap_or_default();
        item.notes = notes.unwrap_or_default();
        item.totp = get(columns.totp).unwrap_or_default();
        item.urls = url.into_iter().collect();
        item.favorite =
            get(columns.favorite).is_some_and(|f| matches!(f.trim(), "1" | "true" | "yes"));
        if let Some(created) = get(columns.created_ms).and_then(|ms| ms.parse::<i64>().ok()) {
            item.created_at = created / 1000;
        }
        if let Some(changed) = get(columns.changed_ms).and_then(|ms| ms.parse::<i64>().ok()) {
            item.updated_at = changed / 1000;
        }
        // Bitwarden CSV: "name: value" per line.
        for line in get(columns.fields).unwrap_or_default().lines() {
            if let Some((name, value)) = line.split_once(": ") {
                item.custom_fields.push(CustomField {
                    name: name.to_owned(),
                    value: value.to_owned(),
                    sensitive: false,
                });
            }
        }
        report.push(item, get(columns.folder));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_export() {
        let csv = "name,url,username,password,note\n\
                   github.com,https://github.com/login,octocat,\"pa,ss\"\"word\",\n\
                   ,https://www.example.org/,me,p2,\"multi\nline\"\n\
                   ,,,,\n";
        let report = import_csv(csv.as_bytes()).unwrap();
        assert_eq!(report.items.len(), 2);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.items[0].password, "pa,ss\"word");
        assert_eq!(report.items[1].title, "example.org");
        assert_eq!(report.items[1].notes, "multi\nline");
    }

    #[test]
    fn firefox_export() {
        let csv = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
                   \"https://accounts.example.com\",\"me@example.com\",\"hunter2\",,\"https://accounts.example.com\",\"{abc}\",\"1700000000000\",\"1700000000000\",\"1700000100000\"\n";
        let report = import_csv(csv.as_bytes()).unwrap();
        let item = &report.items[0];
        assert_eq!(item.title, "accounts.example.com");
        assert_eq!(item.username, "me@example.com");
        assert_eq!(
            (item.created_at, item.updated_at),
            (1_700_000_000, 1_700_000_100)
        );
    }

    #[test]
    fn bitwarden_csv_export() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   Work,1,login,Mail,,\"Recovery: abc\nPIN: 42\",0,https://mail.example,me,pw,JBSWY3DPEHPK3PXP\n\
                   ,,note,Recipe,secret sauce,,0,,,,\n";
        let report = import_csv(csv.as_bytes()).unwrap();
        assert_eq!(report.items.len(), 2);
        let mail = &report.items[0];
        assert!(mail.favorite);
        assert_eq!(mail.totp, "JBSWY3DPEHPK3PXP");
        assert_eq!(mail.custom_fields.len(), 2);
        assert_eq!(report.items[1].kind, ItemKind::SecureNote);
    }

    #[test]
    fn unknown_layout() {
        assert!(matches!(
            import_csv(b"a,b,c\n1,2,3\n"),
            Err(ImportError::UnknownCsvLayout)
        ));
    }
}
