# Bundled data

## `sites-totp.txt` and `sites-passkeys.txt`

The sites that offer two-step sign-in with one-time codes, and those that take passkeys, which
Password health compares a login's websites with, offline (`src/site_lists.rs`). One line per
domain: the domain, a tab, and the page that says how to turn it on (https only, may be empty).
Written by `tools/site-lists/update.ps1`, run by hand; the apps never fetch them.

- **`sites-totp.txt`:** data sourced from [2FA Directory](https://2fa.directory/) by
  [2factorauth](https://github.com/2factorauth/) (`https://api.2fa.directory/v4/totp.json`),
  under the [MIT License](https://github.com/2factorauth/twofactorauth/blob/master/LICENSE.md).
- **`sites-passkeys.txt`:** data sourced from
  [Passkeys Directory](https://passkeys.2fa.directory/) by
  [2factorauth](https://github.com/2factorauth/)
  (`https://passkeys-api.2fa.directory/v1/supported.json`, with each site's other domains), under
  [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).
  Changed: only the domains and the documentation links are kept.

## `eff_large_wordlist.txt`

- **Source:** Electronic Frontier Foundation,
  <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>
  (announced in <https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases>)
- **License:** [Creative Commons Attribution 3.0 United States (CC BY 3.0 US)](https://creativecommons.org/licenses/by/3.0/us/)
  — © Electronic Frontier Foundation. Used without modification.
- **SHA-256:** `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`
- **Contents:** 7,776 words (5 dice rolls each), 12.925 bits of entropy per word.

Verified on download: 7,776 unique dice codes and words, every line `ddddd<TAB>word`, and an
exact match with an independently published copy of the list.
