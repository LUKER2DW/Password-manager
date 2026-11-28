# password-manager-resources (pinned copy)

Two lists of the [password-manager-resources](https://github.com/apple/password-manager-resources)
project, copied unchanged from commit `6c0cedf7b5664cfc41bcc0a0d9e59325d0468271`
(2026-11-19), under its MIT licence (`LICENSE.md`, kept with them):

- `change-password-URLs.json`: the page where each listed site changes a password;
- `password-rules.json`: what each listed site accepts in a password (`passwordrules`).

They are compiled into the apps (`vault_browser::resources`); nothing is fetched at run time.
To bring them up to date, copy both files from a newer commit, name it here, and commit that
alone (`Browser: password-manager-resources at <commit>`).
