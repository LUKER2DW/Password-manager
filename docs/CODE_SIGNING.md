# Code signing policy

> **Status: pending.** Windows code signing through the SignPath Foundation is **not in place
> yet**: the project's application to the SignPath Foundation is pending, and until it is
> accepted the Windows programs are not Authenticode-signed (Windows SmartScreen may warn
> before their first start). The release manifest's signature (below) is how every app checks
> an update; its two public keys are published here once the maintainer makes them.

Free code signing provided by [SignPath.io](https://signpath.io), certificate by
[SignPath Foundation](https://signpath.org).

## What is signed, and with what

| What | Signed with | Checked by |
|---|---|---|
| Every release: `manifest.json`, which lists each file of the release (name, size, SHA-256), the commit it was built from and the APK's certificate | The project's **manifest key** (Ed25519, minisign's format): `manifest.json.minisig`, made in the release workflow | The release workflow itself, before it publishes; the desktop app, the phone app and the sync server (`--app-updates`) before they offer or take anything from a release; the phone again for an update its sync server hands on (spec: [CRYPTO.md](spec/CRYPTO.md) §9) |
| The Windows programs (`vault-desktop.exe`, `vault.exe`, `vault-server-windows-x64.exe`) | Authenticode, certificate by SignPath Foundation (**pending**) | Windows; the release workflow (`apps/desktop/check-exe.ps1 -Authenticode`) |
| The phone app (`vault-mobile-android-<version>.apk`) | The app's Android release key; certificate SHA-256 `5b8f1f7929a87c7bdd1a0b5b0e188fa16d0b06926f230f6ade0f85a5c9b1e971` | The release workflow; Android; and the phone app itself before it hands an update to Android's installer |
| Where each file was built | GitHub's provenance attestations (Sigstore), made by the release workflow | `gh attestation verify` |

The browser extension is not signed by the browsers' stores yet ([ROADMAP.md](ROADMAP.md),
F12).

### The manifest key

Two key pairs, made on the maintainer's computer with `tools/release/make-manifest-keys.ps1`,
each secret half sealed under a password of its own:

- the **primary** signs every release. Its secret half and password are secrets of the
  `android-release` environment, beside the APK's signing key: GitHub hands them only to a
  release run on `main` that the maintainer approved (the environment's required reviewer,
  admins included), and only a run that publishes asks for them;
- the **backup** never goes to GitHub. It stays on the maintainer's computer, to take the
  primary's place if that one ever leaks.

The apps carry both public keys (`RELEASE_KEYS` in `crates/sync-wire/src/releases.rs`) and
take a release signed by either one.

| Key | Public key (minisign) | Key id |
|---|---|---|
| Primary | *pending: published here when the maintainer makes it* | — |
| Backup | *pending* | — |

The signed (trusted) comment of each signature is `vault-release v<version>`: a signature is
bound to its version. The apps refuse a manifest whose version, comment and release tag don't
all agree, and never offer a version that isn't newer than the one installed.

**What this stops:** a file swapped in a published release, or one added to it; a release made
by a push, a pull request or a stolen token without the maintainer's approval (the key isn't
there to sign it); an update changed on its way, or by a sync server that hands it on. **What
it doesn't stop:** someone who takes over the whole GitHub account, approval included (they can
approve a release run of their own making), or who reads the maintainer's signing folder and
its passwords. GitHub can also withhold a release; it can't make an older one count as new.

**Changing the keys.** A new key list is a release of its own, signed with a key the apps
already take: the apps that update to it take the new list from then on. If the primary
leaks, the backup goes into the environment (`make-manifest-keys.ps1 -SetSecrets -Backup`) and
signs a release whose `RELEASE_KEYS` no longer lists the old primary; a new backup is made.
Until every app has updated past it, whoever holds a leaked key could sign a release they would
take.

## Roles

This project has one maintainer, who is the **author** of the code, its **reviewer** and the
**approver** of every release, all three. No one else can commit to `main`, change the release
workflow, approve a release run or sign a release.

| Role | Who |
|---|---|
| Author (committer) | The maintainer, GitHub account [LUKER2DW](https://github.com/LUKER2DW) |
| Reviewer | The maintainer |
| Approver (each release run, and each signing request at SignPath) | The maintainer |

Every account with one of these roles uses multi-factor authentication, on GitHub and at
SignPath. Pull requests from others (Dependabot's included) are never merged as they are: the
change is made again in a commit of the maintainer's after review (AGENTS.md §4.3).

## How a release is made

1. A push to `main` that changes an app runs `.github/workflows/release.yml`: every program is
   built from that commit on GitHub's runners; the Windows programs are checked for their
   exploit protections and their version information (`apps/desktop/check-exe.ps1`).
2. When that version has no release yet, the run waits for the maintainer's approval twice: for
   the APK's signing key (the APK must then carry the release certificate alone) and for the
   manifest key. The `manifest` job builds the signing tool (`tools/release`) before the key is
   near, writes `manifest.json`, signs it, and checks the signature the way the apps do, with
   the keys they carry, and every file against the manifest. A key swapped in the secrets fails
   here, and nothing is published.
3. The files are attested (provenance) and the release is published with them, the manifest
   and its signature.
4. Releases are **immutable** once published (GitHub's immutable releases, turned on for the
   repository): no file of a published release can change or be added, and its tag can't
   move.

Releases are made from `main` only, and only from source in this repository: the workflow's
actions are pinned by commit, its dependencies locked (`Cargo.lock`, `--locked`), and every
dependency checked against known vulnerabilities (`cargo deny check advisories`).

### When SignPath signing starts

Once the SignPath Foundation accepts the project, the release workflow gains, in its `windows`
job, after the build and the protections check: the unsigned programs uploaded as an artifact;
a signing request for them through SignPath's GitHub action
(`signpath/github-action-submit-signing-request`), with the organisation id, project slug,
signing policy and artifact configuration SignPath gives the project, and its API token as a
secret of a GitHub environment that needs the maintainer's approval; the request approved by
the maintainer at SignPath for each release; the signed programs downloaded in place of the
unsigned ones; and `apps/desktop/check-exe.ps1 -Authenticode` run on them, which refuses a
program whose signature isn't valid, isn't timestamped or isn't the SignPath Foundation's. The
release notes then drop their note about SmartScreen. None of this is in the workflow yet: the
slugs exist only once the application is accepted.

Every Windows program carries the same version information: the product "Vault", the project as
its company, and the release's version (`apps/windows-version-info.rs`).

## Checking a download yourself

```bash
# The manifest is the project's (with either public key above):
minisign -Vm manifest.json -P <public key>
# The file is the one the manifest lists:
sha256sum vault-desktop.exe            # PowerShell: Get-FileHash vault-desktop.exe
# It was built by the release workflow, from the manifest's commit:
gh attestation verify vault-desktop.exe --repo LUKER2DW/Password-manager
```

Once Authenticode signing is in place, Windows names "SignPath Foundation" as the publisher
(`Get-AuthenticodeSignature vault-desktop.exe`).

## Privacy

What each app sends, where and when: [PRIVACY.md](PRIVACY.md).
