<h1 align="center">Upgrading to Warden 2.0</h1>

<p align="center">A migration guide for Warden 1.x applications.</p>

<p align="center">
    <a href="https://github.com/dgtlss/warden/actions"><img src="https://github.com/dgtlss/warden/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
    <a href="https://packagist.org/packages/dgtlss/warden"><img src="https://img.shields.io/packagist/v/dgtlss/warden?style=flat-square" alt="Latest Version on Packagist"></a>
    <a href="https://packagist.org/packages/dgtlss/warden"><img src="https://img.shields.io/packagist/dt/dgtlss/warden?style=flat-square" alt="Total Downloads"></a>
    <a href="https://packagist.org/packages/dgtlss/warden"><img src="https://img.shields.io/packagist/php-v/dgtlss/warden?style=flat-square" alt="PHP Version"></a>
    <a href="https://github.com/dgtlss/warden/blob/main/LICENSE"><img src="https://img.shields.io/github/license/dgtlss/warden?style=flat-square" alt="License"></a>
</p>

## Introduction

Warden 2.0 is a CI-first major release. Review the following changes before updating pipeline configuration.

## Supported Platforms

- PHP 8.3–8.5
- Laravel 12–13
- Install with `composer require --dev dgtlss/warden`

Run Warden before the production artifact is rebuilt with `composer install --no-dev`.

## Command changes

| Warden 1.x | Warden 2.0 |
|---|---|
| `--severity=high` | `--fail-on=high` |
| `--output=json` | `--format=json` |
| Shell redirection | `--output-file=report.json` |
| `--npm` | Automatic when `package-lock.json` exists |
| `--ignore-abandoned` | Reviewed suppression or a higher `--fail-on` threshold |
| `--force` | Removed; Warden no longer caches audit results |
| `--no-notify` | Notifications are off by default; use `--notify` to enable |
| `warden:schedule` | Removed; schedule the CI pipeline instead |
| `--output=jenkins` | `--format=junit` |

Warden 2.0 also adds `warden:init`, the default `source` and `platform` audits, and parser-backed application security findings.

The exit code contract is now strict: findings return `1`, while an incomplete or invalid audit returns `2` even when `--fail-on=never` is used.

## Configuration changes

- Remove `cache`, `schedule`, `history`, `sensitive_keys`, `webhook_url`, and top-level `email_recipients` entries.
- Replace wildcard `ignore_findings` rules with entries containing `id`, `reason`, and `expires_at`; add `fingerprint` when only one occurrence should be accepted.
- Replace custom audit implementations with the typed `run(AuditContext): AuditResult` contract.
- Configure notifications only under `warden.notifications`; the legacy webhook path is no longer dispatched.
- Add optional `rule_overrides` values using `enforced`, `advisory`, or `off`; malformed overrides fail before any scan starts.
- Review `audits.source`, `audits.supply_chain`, and `audits.platform` when merging published configuration.

Republish the configuration or merge the new defaults manually:

```bash
php artisan vendor:publish --tag=warden-config --force
```

## Removed runtime features

The production scheduler and audit-history migration were removed because a development dependency is not present after a production `--no-dev` install. Use CI scheduling and persist JSON, SARIF, GitLab, or JUnit artifacts in the CI platform instead.

## Scan-integrity behavior changes

Supplied suppression fingerprints must now be lowercase SHA-256 hashes; omit the key for an intentional rule-wide suppression. Invalid calendar dates and malformed values cause exit 2. Notification delivery remains opt-in and existing finding-only preferences apply to incomplete scans by default; see the 2.1 → 2.2 guidance below. Sanitizers apply only to their output context, so previously hidden cross-context findings can appear. Dotfiles such as `.env.example` and `.github` files now participate in credential scanning. JUnit failures follow the CLI threshold. JSON reports add optional gate and coverage fields; update cached copies of the bundled schema. Registered inactive custom audits remain valid selection IDs and report skipped coverage.


## Notifications: upgrading from 2.1 to 2.2

Existing 2.1 published configs require no change. With `--notify-on-finding` or `notifications.only_on_findings=true`, error-only and ignored-only reports stay silent by default. `--notify` does not override a configured finding-only filter. Neither channel configuration nor error policy enables notifications without a notification flag.

The new `notifications.on_errors` setting is tri-state:

- Omitted or `null`: respect the existing finding-only preference (the bundled default).
- Boolean `true`: explicitly permit incomplete reports even when no active findings remain, provided notifications were requested.
- Boolean `false`: suppress every incomplete report, including reports with active findings. Completed reports still follow existing filters.

If you published the unreleased 2.2 development config from PR #35, it contained `on_errors=true`. Remove that key or set it to `null` to retain your previous finding-only behavior; keep `true` only for a deliberate error-alert opt-in. Rebuild your application's config cache after changing published configuration. Do not overwrite your existing settings merely to add this key.

Delivered incomplete reports explicitly identify scan errors instead of claiming all-clear. Completed emails continue using the existing `warden::mail.enhanced-report` view and application overrides. Incomplete emails use plain text rather than a findings-only custom template that might incorrectly claim success. Recipients and sender preferences are unchanged. See the [notification delivery table](readme.md#notifications) for all combinations.
