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
