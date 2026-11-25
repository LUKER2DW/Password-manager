//! CSV exports with header detection: Chrome, Edge, Brave, Opera, Vivaldi, Firefox, Safari,
//! Bitwarden, 1Password, LastPass, Dashlane, Proton Pass, NordPass, KeePassXC and similar.

use vault_core::{CustomField, ItemData, ItemKind};

use crate::{ImportError, ImportReport, counted, host_of, non_empty};

/// Column name aliases (compared case-insensitively, ignoring spaces and underscores).
const TITLE: &[&str] = &["name", "title", "account", "itemname"];
const URL: &[&str] = &[
    "url", "loginuri", "website", "uri", "address", "loginurl", "weburl", "site",
];
const USERNAME: &[&str] = &["username", "loginusername", "login", "user", "username1"];
/// Used when the username column is missing or empty (Proton Pass has both).
const EMAIL: &[&str] = &["email", "emailaddress", "loginemail"];
const PASSWORD: &[&str] = &["password", "loginpassword"];
const NOTES: &[&str] = &[
    "note",
    "notes",
    "extra",
    "comments",
    "comment",
    "notesplain",
];
/// Dashlane "otpSecret"/"otpUrl", 1Password and Safari "OTPAuth".
const TOTP: &[&str] = &[
    "totp",
    "logintotp",
    "otpauth",
    "otp",
    "otpsecret",
    "otpurl",
    "2fa",
];
const FAVORITE: &[&str] = &["favorite", "fav"];
const REPROMPT: &[&str] = &["reprompt"];
const KIND: &[&str] = &["type"];
const FIELDS: &[&str] = &["fields"];
/// Bitwarden CSV "folder", LastPass "grouping", KeePassXC "group", Dashlane "category",
/// Proton Pass "vault".
const FOLDER: &[&str] = &["folder", "grouping", "group", "category", "vault"];
/// Firefox: milliseconds since the Unix epoch.
const CREATED_MS: &[&str] = &["timecreated"];
const CHANGED_MS: &[&str] = &["timepasswordchanged"];

struct Columns {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    email: Option<usize>,
    password: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
    favorite: Option<usize>,
    reprompt: Option<usize>,
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
            email: find(EMAIL),
            password: find(PASSWORD),
            notes: find(NOTES),
            totp: find(TOTP),
            favorite: find(FAVORITE),
            reprompt: find(REPROMPT),
            kind: find(KIND),
            fields: find(FIELDS),
            folder: find(FOLDER),
            created_ms: find(CREATED_MS),
            changed_ms: find(CHANGED_MS),
        }
    }

    fn is_usable(&self) -> bool {
        self.password.is_some()
            || self.username.is_some()
            || self.email.is_some()
            || self.url.is_some()
    }
}

/// Imports a CSV export. The first row must be a header.
pub(crate) fn import_csv(bytes: &[u8]) -> Result<ImportReport, ImportError> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(bytes);
    let columns = Columns::from_headers(reader.headers()?);
    if !columns.is_usable() {
        return Err(ImportError::UnknownCsvLayout);
    }

    let mut report = ImportReport::default();
    // Custom fields read, and how many of them were hidden for their names.
    let (mut fields_read, mut fields_hidden) = (0usize, 0usize);
    for (row_index, record) in reader.records().enumerate() {
        let record = record?;
        let get = |column: Option<usize>| {
            column
                .and_then(|i| record.get(i))
                .map(str::to_owned)
                .and_then(|v| non_empty(Some(v)))
        };

        // Text cells may carry the mark our export puts on formula-like text.
        let text = |column: Option<usize>| get(column).map(crate::export::from_text);

        let title = text(columns.title);
        let url = text(columns.url);
        let username = text(columns.username).or_else(|| text(columns.email));
        let password = get(columns.password);
        let notes = text(columns.notes);
        let totp = get(columns.totp);
        let fields = text(columns.fields);
        // Nothing in any of them: a row that holds only fields (a card in our own export) or
        // only a name is an item.
        if [&title, &url, &username, &password, &notes, &totp, &fields]
            .iter()
            .all(|cell| cell.is_none())
        {
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
        let title = title
            .or_else(|| url.as_deref().and_then(host_of))
            .unwrap_or_else(|| "Untitled".into());

        let mut item = ItemData::new(kind, &title);
        item.username = username.unwrap_or_default();
        item.password = password.unwrap_or_default();
        item.notes = notes.unwrap_or_default();
        item.totp = totp.unwrap_or_default();
        item.urls = url.into_iter().collect();
        item.favorite =
            get(columns.favorite).is_some_and(|f| matches!(f.trim(), "1" | "true" | "yes"));
        item.reprompt =
            get(columns.reprompt).is_some_and(|f| matches!(f.trim(), "1" | "true" | "yes"));
        if let Some(created) = get(columns.created_ms).and_then(|ms| ms.parse::<i64>().ok()) {
            item.created_at = created / 1000;
        }
        if let Some(changed) = get(columns.changed_ms).and_then(|ms| ms.parse::<i64>().ok()) {
            item.updated_at = changed / 1000;
            item.password_changed_at = changed / 1000;
        }
        // KeePassXC exports its root group as "Root/…".
        let folder = text(columns.folder).map(|folder| {
            let trimmed = folder.strip_prefix("Root/").unwrap_or(&folder);
            if trimmed == "Root" {
                String::new()
            } else {
                trimmed.to_owned()
            }
        });
        // Bitwarden CSV: "name: value" per line. A line without a name goes on with the value
        // before it (a value of several lines). No layout read here marks a field hidden, so
        // one whose name looks secret is hidden rather than shown.
        for line in fields.as_deref().unwrap_or_default().lines() {
            let (name, value, sensitive) = match line.split_once(": ") {
                Some((name, value)) => (name, value, looks_secret(name)),
                None => {
                    if let Some(last) = item.custom_fields.last_mut() {
                        last.value.push('\n');
                        last.value.push_str(line);
                        continue;
                    }
                    if line.trim().is_empty() {
                        continue;
                    }
                    // A value with no name at all: nothing says it isn't a secret.
                    ("Field", line, true)
                }
            };
            fields_read += 1;
            fields_hidden += usize::from(sensitive);
            item.custom_fields.push(CustomField {
                name: name.to_owned(),
                value: value.to_owned(),
                sensitive,
            });
        }
        report.push(item, folder);
    }
    if fields_read > 0 {
        let shown = fields_read - fields_hidden;
        let warning = if shown == 0 {
            format!(
                "custom fields: CSV keeps no hidden mark; {} named like a secret {} hidden",
                counted(fields_read, "field", "fields"),
                if fields_read == 1 { "was" } else { "were" }
            )
        } else {
            format!(
                "custom fields: CSV keeps no hidden mark, so only fields named like a secret (PIN, password, code…) were hidden, {fields_hidden} of {fields_read}; check the other {shown} and hide any that hold a secret"
            )
        };
        // First, as it is about the whole file: the app shows only the first few.
        report.warnings.insert(0, warning);
    }
    Ok(report)
}

/// Parts of a field's name that say its value is a secret: a word of the name that starts or
/// ends with one of them ("PIN", "API key", "passcode", "Recovery codes", "Senha"). A name
/// taken for a secret by mistake only hides a value the person can still show.
const SECRET_PARTS: &[&str] = &[
    "pass",
    "pwd",
    "pin",
    "secret",
    "token",
    "key",
    "cvv",
    "ccv",
    "cvc",
    "csc",
    "otp",
    "2fa",
    "mfa",
    "recovery",
    "backup",
    "code",
    "answer",
    "seed",
    "mnemonic",
    "private",
    "puk",
    "ssn",
    "iban",
    "credential",
    // Words other languages use for a password, a secret, a key or a code.
    "senha",
    "clave",
    "contrase",
    "geheim",
    "segredo",
    "chave",
    "codigo",
    "código",
    "resposta",
    "recupera",
    "semente",
];

/// Whether a custom field named `name` holds a secret, judged by its name alone: the CSV
/// layouts read here keep no hidden mark. This app's own fields that are never secret (an SSH
/// key's public half, a card's expiry) are told apart; a card's "Number" is a secret. No name
/// says nothing: the value is hidden.
fn looks_secret(name: &str) -> bool {
    use vault_core::{card, ssh};
    let name = name.trim();
    if name.is_empty() {
        return true;
    }
    if [
        ssh::PUBLIC_KEY_FIELD,
        ssh::FINGERPRINT_FIELD,
        ssh::KEY_TYPE_FIELD,
        card::EXPIRY,
        card::BRAND,
        crate::json::REFERENCE_FIELD,
    ]
    .iter()
    .any(|plain| plain.eq_ignore_ascii_case(name))
    {
        return false;
    }
    if name.eq_ignore_ascii_case(card::NUMBER) {
        return true;
    }
    let words = words(name);
    let has = |wanted: &str| words.iter().any(|word| word == wanted);
    // A card's or an account's number is a secret; a public key is published on purpose (but
    // "Public library PIN" is still a PIN).
    if has("number") && (has("card") || has("account")) {
        return true;
    }
    let public = has("public");
    words
        .iter()
        .filter(|word| !(public && matches!(word.as_str(), "key" | "keys")))
        .any(|word| {
            SECRET_PARTS
                .iter()
                .any(|part| word.starts_with(part) || word.ends_with(part))
        })
}

/// The words of a name, lower case: split at anything but letters and digits and where a
/// lower-case letter meets an upper-case one ("apiKey" → "api", "key").
fn words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut lower_before = false;
    for c in name.chars() {
        if !c.is_alphanumeric() {
            lower_before = false;
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            continue;
        }
        if c.is_uppercase() && lower_before && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        lower_before = c.is_lowercase();
        word.extend(c.to_lowercase());
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
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
    fn csv_with_folder_type_and_fields() {
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
    fn other_managers() {
        // Proton Pass: email used when the username is empty; "vault" becomes the folder.
        let proton = "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n\
                      login,Shop,https://shop.example,me@mail.example,,pw1,,,1,2,Personal\n";
        let report = import_csv(proton.as_bytes()).unwrap();
        assert_eq!(report.items[0].username, "me@mail.example");
        assert_eq!(report.folders[0].as_deref(), Some("Personal"));
        // Dashlane: otpSecret and category.
        let dashlane = "username,username2,username3,title,password,note,url,category,otpSecret\n\
                        me,,,Mail,pw2,,https://mail.example,Work,JBSWY3DPEHPK3PXP\n";
        let report = import_csv(dashlane.as_bytes()).unwrap();
        assert_eq!(report.items[0].totp, "JBSWY3DPEHPK3PXP");
        assert_eq!(report.folders[0].as_deref(), Some("Work"));
        // KeePassXC: "Root/" dropped from the group path.
        let keepassxc = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\
                         \"Root/Games\",\"Steam\",\"me\",\"pw3\",\"https://store.example\",\"\",\"\",\"0\",\"\",\"\"\n\
                         \"Root\",\"Bank\",\"me\",\"pw4\",\"\",\"\",\"\",\"0\",\"\",\"\"\n";
        let report = import_csv(keepassxc.as_bytes()).unwrap();
        assert_eq!(report.folders, [Some("Games".to_owned()), None]);
        // 1Password / Safari: OTPAuth.
        let onepassword = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
                           Git,https://git.example,me,pw5,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP,true,false,,\n";
        let report = import_csv(onepassword.as_bytes()).unwrap();
        assert!(report.items[0].totp.starts_with("otpauth://"));
        assert!(report.items[0].favorite);
    }

    #[test]
    fn custom_fields_named_like_secrets_come_back_hidden() {
        let csv = "type,name,login_username,login_password,fields\n\
                   login,Mail,me,pw,\"PIN: 42\nPlan: family\napiKey: abc\nSecurity code: 123\nRecovery codes: aaaa bbbb\nSecurity question: first pet\"\n";
        let report = import_csv(csv.as_bytes()).unwrap();
        let hidden: Vec<(&str, bool)> = report.items[0]
            .custom_fields
            .iter()
            .map(|f| (f.name.as_str(), f.sensitive))
            .collect();
        assert_eq!(
            hidden,
            [
                ("PIN", true),
                ("Plan", false),
                ("apiKey", true),
                ("Security code", true),
                ("Recovery codes", true),
                ("Security question", false),
            ]
        );
        // And the person is told that CSV kept no hidden mark, and what was done.
        assert_eq!(
            report.warnings,
            [
                "custom fields: CSV keeps no hidden mark, so only fields named like a secret (PIN, password, code…) were hidden, 4 of 6; check the other 2 and hide any that hold a secret"
            ]
        );
        let all = "name,password,fields\nMail,pw,PIN: 42\n";
        assert_eq!(
            import_csv(all.as_bytes()).unwrap().warnings,
            ["custom fields: CSV keeps no hidden mark; 1 field named like a secret was hidden"]
        );
        // No fields, no warning.
        let none = "name,password,fields\nMail,pw,\n";
        assert!(import_csv(none.as_bytes()).unwrap().warnings.is_empty());
    }

    #[test]
    fn which_names_look_secret() {
        for name in [
            "Password",
            "Passcode",
            "Wi-Fi passphrase",
            "PIN",
            "myPIN",
            "PIN-Code",
            "API key",
            "apiKey",
            "Auth token",
            "Client secret",
            "CVV",
            "2FA backup",
            "Recovery codes",
            "Seed phrase",
            "Private key",
            "Answer",
            "Number",
            "Card number",
            "Account number",
            "Public library PIN",
            "IBAN",
            "Senha",
            "Resposta secreta",
            "Códigos de recuperação",
            "Contraseña",
            "Código",
        ] {
            assert!(looks_secret(name), "{name}");
        }
        for name in [
            "Plan",
            "Shipping address",
            "Security question",
            "Email",
            "Phone number",
            "Customer ID",
            "Public key",
            "SSH public key",
            "Public keys",
            "Fingerprint",
            "Key type",
            "Expiry",
            "Brand",
            "Website (not filled)",
        ] {
            assert!(!looks_secret(name), "{name}");
        }
        // No name: nothing says the value isn't a secret.
        assert!(looks_secret("") && looks_secret("  "));
    }

    #[test]
    fn a_row_is_empty_only_when_nothing_in_it_can_be_read() {
        // What our own CSV writes for a card with no holder, an item that is only a name, and
        // a lone one-time code secret.
        let csv = "folder,type,name,notes,fields,login_uri,login_username,login_password,login_totp\n\
                   ,note,Visa,,\"Number: 4111111111111111\n: 737\",,,,\n\
                   ,login,Shop,,,,,,\n\
                   ,login,,,,,,,JBSWY3DPEHPK3PXP\n\
                   Work,login,,,,,,,\n";
        let report = import_csv(csv.as_bytes()).unwrap();
        let titles: Vec<&str> = report.items.iter().map(|i| i.title.as_str()).collect();
        assert_eq!(titles, ["Visa", "Shop", "Untitled"]);
        let card: Vec<(&str, &str, bool)> = report.items[0]
            .custom_fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str(), f.sensitive))
            .collect();
        // The field without a name is hidden too.
        assert_eq!(
            card,
            [("Number", "4111111111111111", true), ("", "737", true)]
        );
        assert_eq!(report.items[2].totp, "JBSWY3DPEHPK3PXP");
        // What the whole file is told comes before its rows.
        assert_eq!(report.warnings.len(), 2, "{:?}", report.warnings);
        assert!(report.warnings[0].starts_with("custom fields: "));
        assert_eq!(report.warnings[1], "row 5: empty, skipped");
    }

    #[test]
    fn a_field_value_of_several_lines_comes_back_whole() {
        let csv = "name,password,fields\n\
                   Mail,pw,\"Address: 1 Main St\nSpringfield\n\nPIN: 42\"\n\
                   Other,pw,\"no name here\"\n";
        let report = import_csv(csv.as_bytes()).unwrap();
        let fields: Vec<(&str, &str)> = report.items[0]
            .custom_fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            fields,
            [("Address", "1 Main St\nSpringfield\n"), ("PIN", "42")]
        );
        // A line with no name is kept, hidden: nothing says it isn't a secret.
        let lone = &report.items[1].custom_fields;
        assert_eq!(lone.len(), 1);
        assert!(lone[0].name == "Field" && lone[0].value == "no name here" && lone[0].sensitive);
    }

    #[test]
    fn our_own_csv_export_comes_back_with_its_hidden_fields_hidden() {
        let mut vault = vault_core::Vault::create(
            "csv test passphrase",
            &vault_core::SecretKey::generate().unwrap(),
            None,
            vault_core::KdfParams::minimum().unwrap(),
        )
        .unwrap();
        let mut item = ItemData::login("Bank", "me", "pw", "https://bank.example");
        for (name, value, sensitive) in [
            ("PIN", "1234", true),
            ("Branch", "Main\nStreet", false),
            ("Telephone banking code", "9876", true),
        ] {
            item.custom_fields.push(CustomField {
                name: name.into(),
                value: value.into(),
                sensitive,
            });
        }
        vault.add_item(&item).unwrap();
        let csv = crate::export_csv(&vault).unwrap();
        let report = import_csv(csv.as_bytes()).unwrap();
        assert_eq!(report.items[0].custom_fields, item.custom_fields);
    }

    #[test]
    fn unknown_layout() {
        assert!(matches!(
            import_csv(b"a,b,c\n1,2,3\n"),
            Err(ImportError::UnknownCsvLayout)
        ));
    }
}
