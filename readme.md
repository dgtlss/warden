# Warden

[![Latest Version on Packagist](https://img.shields.io/packagist/v/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![Total Downloads](https://img.shields.io/packagist/dt/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![License](https://img.shields.io/packagist/l/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![PHP Version Require](https://img.shields.io/packagist/php-v/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
![GitHub repo size](https://img.shields.io/github/repo-size/dgtlss/warden)

Warden is a CI-first security audit package for Laravel applications.

It is designed to give your pipeline an extra layer of protection before code is merged or deployed. Warden audits dependencies, Laravel configuration, writable directories, repository secrets, GitHub Actions workflows, and container files, then returns CI-friendly exit codes and report formats.

Warden also works well locally. You can run the same checks before pushing, adopt stricter rules gradually with baselines, and use `warden:resolve` to preview or apply dependency remediations outside CI.

## What Warden is good at

- Catching vulnerable Composer dependencies with `composer audit`
- Catching vulnerable JavaScript dependencies when you opt into `--npm`
- Flagging risky Laravel runtime posture and production misconfiguration
- Detecting likely committed secrets in tracked config and CI files
- Auditing GitHub Actions workflows for dangerous defaults
- Auditing Dockerfiles and Compose files for common security mistakes
- Producing output that fits real CI workflows: JSON, GitHub, GitLab, Jenkins, SARIF, CycloneDX, Markdown, and HTML

## Requirements

| Requirement | Version |
| --- | --- |
| PHP | `>= 8.3` |
| Laravel / Illuminate | `^7.0` through `^13.0` |

## Installation

Warden is usually best installed as a development dependency:

```bash
composer require dgtlss/warden --dev
```

If you plan to run Warden from scheduled tasks in non-development environments, you can install it without `--dev`.

Publish the config file:

```bash
php artisan vendor:publish --tag=warden-config
```

That creates `config/warden.php`, which is where most of the newer Warden features are configured.

## Quick start

Run the default audit profile:

```bash
php artisan warden:audit
```

Include JavaScript dependency auditing:

```bash
php artisan warden:audit --npm
```

Validate setup and integration readiness:

```bash
php artisan warden:doctor
```

Start with a machine-readable CI output:

```bash
php artisan warden:audit --output=github --no-notify
```

## Exit codes

`warden:audit` is designed for CI and returns predictable exit codes:

| Command | Exit code | Meaning |
| --- | --- | --- |
| `warden:audit` | `0` | No active findings |
| `warden:audit` | `1` | Active findings were detected |
| `warden:audit` | `2` | One or more audits failed to execute correctly |
| `warden:syntax` | `0` | No syntax findings |
| `warden:syntax` | `1` | Syntax findings were detected |
| `warden:syntax` | `2` | The syntax audit itself failed |
| `warden:resolve` | `0` | Preview succeeded, or apply succeeded and no active findings remained |
| `warden:resolve` | `1` | Resolve was blocked, failed, or left active findings after apply |

## Profiles

Warden supports profiles so you can adopt stricter auditing without breaking existing pipelines overnight.

The default profile is:

```php
'profile' => 'legacy',
```

Available profiles:

| Profile | Purpose |
| --- | --- |
| `legacy` | Preserves the original Warden footprint for existing users |
| `recommended` | Stronger CI-first coverage for most teams |
| `ci-strict` | The broadest CI-focused ruleset |
| `runtime-safe` | Safer for scheduled or in-environment runtime auditing |

If you want the fuller v2 ruleset, the usual next step is to change:

```php
'profile' => 'recommended',
```

## What each profile audits

| Audit family | `legacy` | `recommended` | `ci-strict` | `runtime-safe` |
| --- | --- | --- | --- | --- |
| Composer dependency audit | Yes | Yes | Yes | Yes |
| Environment audit | Yes | Yes | Yes | Yes |
| Storage audit | Yes | Yes | Yes | Yes |
| Debug / production posture audit | Yes | Yes | Yes | Yes |
| Laravel posture audit | No | Yes | Yes | Yes |
| Repository secrets audit | No | Yes | Yes | No |
| GitHub Actions workflow audit | No | Yes | Yes | No |
| Docker / container audit | No | Yes | Yes | No |
| NPM / pnpm / Yarn dependency audit | Optional via `--npm` | Optional via `--npm` | Optional via `--npm` | Optional via `--npm` |
| Custom audits | Yes | Yes | Yes | Yes |

## Audit coverage

Warden currently includes these built-in audit families:

| Audit | What it checks |
| --- | --- |
| Composer | Vulnerabilities from `composer audit`, plus abandoned packages |
| NPM | Vulnerabilities using `npm audit`, `pnpm audit`, or `yarn npm audit` depending on the detected lockfile |
| Environment | Missing `.env`, missing `.env` ignore rule, and missing sensitive keys you define |
| Storage | Missing or non-writable Laravel runtime directories |
| Debug mode | `APP_DEBUG` in production, dev packages in production, exposed testing routes, Telescope/Horizon exposure checks |
| Laravel posture | Missing `APP_KEY`, insecure session settings, risky CORS settings, and public storage exposure |
| Repository secrets | Likely committed secrets in `.env.example`, config files, Docker files, and GitHub workflow files |
| CI workflow | Risky GitHub Actions usage such as `pull_request_target`, `write-all`, unpinned third-party actions, and unsafe shell interpolation |
| Docker security | Copied `.env` files, `chmod 777`, explicit root runtime users, and dev dependency installs in container builds |

## Command reference

| Command | Purpose |
| --- | --- |
| `php artisan warden:audit` | Run the main Warden audit flow |
| `php artisan warden:syntax` | Run the standalone PHP syntax audit |
| `php artisan warden:baseline` | Generate or refresh a baseline suppression file |
| `php artisan warden:doctor` | Check binaries, history readiness, cloud readiness, and notification config |
| `php artisan warden:history` | Show recent persisted audit runs |
| `php artisan warden:history:prune` | Delete old audit history entries |
| `php artisan warden:resolve` | Preview or apply dependency remediation plans |
| `php artisan warden:schedule` | Enable, disable, or inspect scheduled audits |
| `php artisan warden:sync` | Sync the latest persisted run to an optional Warden Cloud endpoint |

### `warden:audit` options

| Option | Purpose |
| --- | --- |
| `--no-notify` | Suppress notifications |
| `--npm` | Include JavaScript dependency auditing |
| `--ignore-abandoned` | Suppress detailed abandoned-package reporting and notifications |
| `--output=` | Choose `json`, `github`, `gitlab`, `jenkins`, `sarif`, `cyclonedx`, `markdown`, or `html` |
| `--severity=` | Filter active findings by minimum severity |
| `--force` | Ignore cached audit results and run fresh |

### `warden:baseline` options

| Option | Purpose |
| --- | --- |
| `--path=` | Write the baseline to a custom location |
| `--reason=` | Set a reason on every generated baseline entry |
| `--expires=` | Set an optional expiry timestamp for generated entries |
| `--npm` | Include JavaScript findings in the baseline |
| `--force` | Ignore cached audit results while generating the baseline |

### `warden:resolve` options

| Option | Purpose |
| --- | --- |
| `--apply` | Apply the generated resolution plan |
| `--dry-run` | Explicit preview mode |
| `--package=` | Limit the plan to one package |
| `--source=` | Limit the plan to `composer` or `npm` |
| `--rule=` | Limit the plan to one rule identifier |
| `--with-dev` | Allow development dependencies into the plan |
| `--allow-major` | Allow high-risk major upgrade operations |
| `--branch` | Create a `codex/warden-resolve-*` branch before apply |
| `--no-verify` | Skip post-apply verification |
| `--force-ci` | Override the default CI guard |
| `--allow-dirty` | Allow apply mode on a dirty working tree |

## Output formats

| Format | Best use |
| --- | --- |
| `json` | General automation or custom tooling |
| `github` | GitHub Actions workflow annotations |
| `gitlab` | GitLab dependency scanning-style output |
| `jenkins` | Jenkins-oriented JSON payload |
| `sarif` | GitHub code scanning or other SARIF consumers |
| `cyclonedx` | SBOM and dependency-security workflows |
| `markdown` | Pull request artifacts or human review |
| `html` | Human-readable downloadable report |

Examples:

```bash
php artisan warden:audit --output=json > warden.json
php artisan warden:audit --output=sarif > warden.sarif
php artisan warden:audit --output=cyclonedx > warden.cdx.json
php artisan warden:audit --output=markdown > warden-report.md
php artisan warden:audit --output=html > warden-report.html
```

## Common workflows

### 1. Local audit before you push

```bash
php artisan warden:audit --npm --no-notify
```

### 2. CI audit with workflow annotations

```bash
php artisan warden:audit --output=github --no-notify
```

### 3. Gradual adoption with a baseline

```bash
php artisan warden:baseline --reason="Accepted during migration" --expires="2026-12-31T00:00:00+00:00"
```

Then commit the generated `.warden-baseline.json` file.

### 4. Local remediation flow

Preview what Warden would do:

```bash
php artisan warden:resolve
```

Apply a dependency remediation plan:

```bash
php artisan warden:resolve --apply
```

Focus only on Composer or only on JavaScript:

```bash
php artisan warden:resolve --source=composer
php artisan warden:resolve --source=npm
```

### 5. Scheduled auditing

```bash
php artisan warden:schedule --enable
php artisan warden:schedule --status
```

## Baselines and suppressions

Baselines are the safest way to adopt Warden on an existing codebase without failing the build on every historical issue.

By default, `warden:baseline` writes to:

```text
.warden-baseline.json
```

Warden suppresses matching findings by fingerprint first, then by fallback fields such as `rule_id`, `package`, and `file`.

You can also define manual suppressions in `config/warden.php`:

```php
'policy' => [
    'suppressions' => [
        [
            'fingerprint' => 'sha256...',
            'reason' => 'Accepted until dependency upgrade lands.',
            'expires_at' => '2026-12-31T00:00:00+00:00',
        ],
    ],
],
```

## Auto resolve

`warden:resolve` is intentionally conservative in v1.

What it does today:

- It is preview-first and does not change files unless you pass `--apply`
- It only targets dependency findings
- It supports Composer findings first, then JavaScript dependency findings when a supported lockfile and package manager are available
- It records preview and apply attempts in history metadata when history persistence is enabled

What it will auto-plan:

- Direct Composer dependency updates with `composer update <package> --with-all-dependencies --no-interaction`
- Direct abandoned Composer dependency replacement when Composer provides an explicit replacement
- Direct JavaScript dependency updates for `npm`, `pnpm`, or `yarn`
- Lockfile refresh plans for some transitive JavaScript findings

Safety rules:

- `warden:audit` never mutates your project
- `warden:resolve` is blocked in CI by default unless you pass `--force-ci` or change config
- Dirty working trees are blocked in apply mode unless you pass `--allow-dirty` or change config
- High-risk major updates require `--allow-major`
- Post-apply verification runs `composer phpstan` and `vendor/bin/phpunit tests/` when those commands are available, then reruns the audit

## Configuration

Warden uses two configuration styles:

- Existing operational knobs continue to work well through environment variables
- Newer Warden product features are configured directly in `config/warden.php`

### Environment-backed settings

These are the main settings that still make sense in `.env`:

| Area | Settings |
| --- | --- |
| App / notifications | `WARDEN_APP_NAME`, `WARDEN_WEBHOOK_URL`, `WARDEN_SLACK_WEBHOOK_URL`, `WARDEN_DISCORD_WEBHOOK_URL`, `WARDEN_TEAMS_WEBHOOK_URL`, `WARDEN_EMAIL_RECIPIENTS`, `WARDEN_EMAIL_FROM`, `WARDEN_EMAIL_FROM_NAME` |
| Cache and execution | `WARDEN_CACHE_ENABLED`, `WARDEN_CACHE_DURATION`, `WARDEN_CACHE_DRIVER`, `WARDEN_PARALLEL_EXECUTION`, `WARDEN_MAX_CONCURRENCY`, `WARDEN_AUDIT_TIMEOUT`, `WARDEN_PHP_SYNTAX_AUDIT_ENABLED` |
| Scheduling | `WARDEN_SCHEDULE_ENABLED`, `WARDEN_SCHEDULE_FREQUENCY`, `WARDEN_SCHEDULE_TIME`, `WARDEN_SCHEDULE_TIMEZONE` |

Example notification config:

```env
WARDEN_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
WARDEN_EMAIL_RECIPIENTS=security@example.com,ops@example.com
WARDEN_EMAIL_FROM=security@example.com
WARDEN_EMAIL_FROM_NAME="Warden"
```

### Config-only sections

These are better set in `config/warden.php`:

| Section | Purpose |
| --- | --- |
| `profile` | Active audit profile |
| `profiles` | Profile descriptions |
| `baseline` | Baseline enablement and path |
| `policy` | Manual suppressions and Composer policy |
| `history` | Audit run persistence settings |
| `integrations` | Optional manual CI metadata overrides |
| `cloud` | Optional hosted sync settings |
| `resolve` | Auto-resolve behavior and package-manager gating |
| `sensitive_keys` | Environment variables your app considers security-critical |
| `custom_audits` | Organization-specific audit classes |

Example:

```php
'profile' => 'recommended',

'baseline' => [
    'enabled' => true,
    'path' => '.warden-baseline.json',
],

'policy' => [
    'composer' => [
        'include_dev_dependencies' => true,
    ],
],

'history' => [
    'enabled' => true,
    'table' => 'warden_audit_history',
    'retention_days' => 90,
],

'resolve' => [
    'enabled' => true,
    'allow_in_ci' => false,
    'default_verify' => true,
    'allow_dirty' => false,
    'auto_branch' => false,
    'package_managers' => [
        'composer' => true,
        'npm' => true,
        'pnpm' => true,
        'yarn' => true,
    ],
],

'sensitive_keys' => [
    'DB_PASSWORD',
    'STRIPE_SECRET_KEY',
    'AWS_SECRET_ACCESS_KEY',
],
```

## Notifications

Warden supports:

- Slack
- Discord
- Microsoft Teams
- Email
- A legacy generic webhook setting for backward compatibility

Notifications are sent for active findings unless you run:

```bash
php artisan warden:audit --no-notify
```

## Audit history

History is disabled by default.

If you want persisted run history:

1. Enable it in `config/warden.php`
2. Run your app migrations

```php
'history' => [
    'enabled' => true,
    'table' => 'warden_audit_history',
    'retention_days' => 90,
],
```

```bash
php artisan migrate
```

Then you can use:

```bash
php artisan warden:history
php artisan warden:history --limit=25
php artisan warden:history:prune --days=30
```

## Warden Cloud

Core Warden works fully offline. Cloud sync is optional and disabled by default.

If you enable `warden.cloud.enabled` and provide a `base_url` and `token`, Warden can sync the latest persisted run with:

```bash
php artisan warden:sync
```

If `warden.cloud.auto_sync` is enabled, Warden will also attempt to sync after an audit run when cloud configuration is complete.

## Scheduling

Warden includes a convenience command for scheduled audits:

```bash
php artisan warden:schedule --enable
php artisan warden:schedule --status
php artisan warden:schedule --disable
```

Important note: `warden:schedule` is a convenience layer around the existing schedule env settings and updates `WARDEN_SCHEDULE_ENABLED` in your `.env` file. If your team manages config entirely in code or uses immutable environment management, set the schedule values directly instead of relying on the command.

You still need Laravel's scheduler running:

```bash
* * * * * cd /path-to-your-project && php artisan schedule:run >> /dev/null 2>&1
```

## Custom audits

Register custom audits in `config/warden.php`:

```php
'custom_audits' => [
    \App\Audits\ProductionDebugAudit::class,
],
```

Each custom audit must implement `Dgtlss\Warden\Contracts\CustomAudit`.

Example:

```php
<?php

namespace App\Audits;

use Dgtlss\Warden\Contracts\CustomAudit;

class ProductionDebugAudit implements CustomAudit
{
    private array $findings = [];

    public function audit(): bool
    {
        if (config('app.env') === 'production' && config('app.debug') === true) {
            $this->findings[] = [
                'rule_id' => 'custom.production-debug.enabled',
                'category' => 'laravel',
                'severity' => 'critical',
                'package' => 'application',
                'title' => 'Debug mode is enabled in production',
                'description' => 'APP_DEBUG should be disabled in production.',
                'file' => '.env',
                'remediation' => 'Set APP_DEBUG=false before deploying.',
            ];
        }

        return $this->findings === [];
    }

    public function getFindings(): array
    {
        return $this->findings;
    }

    public function getName(): string
    {
        return 'Production Debug Audit';
    }

    public function getDescription(): string
    {
        return 'Ensures APP_DEBUG is not enabled in production.';
    }

    public function shouldRun(): bool
    {
        return true;
    }
}
```

Supported custom finding fields include:

- `rule_id`
- `category`
- `severity`
- `title`
- `description`
- `package`
- `file`
- `line`
- `remediation`
- `references`

Additional keys are preserved as metadata, which means custom audits can also attach richer information if your reporting pipeline needs it.

## CI example

GitHub Actions example:

```yaml
name: Warden

on:
  push:
  pull_request:

jobs:
  warden:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'

      - name: Install dependencies
        run: composer install --no-interaction --prefer-dist

      - name: Run Warden
        run: php artisan warden:audit --output=github --no-notify
```

For SARIF-based workflows, swap the output format:

```bash
php artisan warden:audit --output=sarif --no-notify
```

## Troubleshooting

### `composer audit` failed to run

Warden depends on the underlying package manager commands. If `composer audit` cannot reach advisory data or cannot produce JSON output, Warden will treat that as an audit execution failure.

### JavaScript audit says a lockfile is missing

Warden expects one of these files when `--npm` is used:

- `package-lock.json`
- `pnpm-lock.yaml`
- `yarn.lock`

### `warden:history` says the table is missing

Enable `warden.history.enabled`, then run:

```bash
php artisan migrate
```

### `warden:resolve` says nothing is resolvable

Not every finding can be fixed automatically. Warden only auto-plans deterministic dependency remediations in v1. Configuration, secret, CI, container, and most transitive dependency findings still require manual review.

### The stricter profile is too noisy for an existing app

That is the exact use case for baselines.

Start with:

```bash
php artisan warden:baseline --reason="Initial adoption"
```

Then move from `legacy` to `recommended` once the baseline is in place.
