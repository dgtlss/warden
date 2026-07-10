# Warden

Warden is a deterministic Laravel security gate for CI and deployment pipelines. It audits locked production dependencies, supply-chain configuration, and high-confidence Laravel production settings without becoming part of the deployed application.

## Requirements

- PHP 8.3–8.5
- Laravel 12 or 13
- Composer 2
- npm only when a `package-lock.json` is present

## Installation

Install Warden as a development dependency:

```bash
composer require --dev dgtlss/warden
```

Run Warden **before** pruning development dependencies from the production artifact:

```bash
composer install --no-interaction
php artisan warden:audit --profile=production --scope=production
composer install --no-dev --no-interaction --optimize-autoloader
```

Initialize Warden safely and optionally generate a dedicated CI file:

```bash
php artisan warden:init --ci=github
# or: --ci=gitlab|both|none
```

`warden:init` never overwrites an existing `config/warden.php` or root GitLab pipeline. `--force` may replace only Warden-owned generated CI files. Publishing with `vendor:publish --tag=warden-config` remains available for manual setups.

## CI usage

The default command uses the CI profile, audits production dependencies, reports every finding, and fails on low severity or higher:

```bash
php artisan warden:audit
```

Common examples:

```bash
# Gate only on high and critical findings while still reporting everything
php artisan warden:audit --fail-on=high

# Validate effective production configuration
php artisan warden:audit --profile=production

# Audit production and development dependencies
php artisan warden:audit --scope=all

# Select or skip audits
php artisan warden:audit --only=supply-chain,composer,laravel-config,platform,source
php artisan warden:audit --skip=npm,storage

# Produce CI artifacts
php artisan warden:audit --format=json --output-file=warden-report.json
php artisan warden:audit --format=sarif --output-file=warden.sarif
php artisan warden:audit --format=gitlab --output-file=gl-dependency-scanning-report.json
php artisan warden:audit --format=junit --output-file=warden-junit.xml
```

Machine formats never mix progress or diagnostic prose into stdout. Scanner failures are included in the report and exit with code `2`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every audit completed and no blocking finding met `--fail-on` |
| `1` | One or more blocking findings met `--fail-on` |
| `2` | Configuration, tool, timeout, malformed output, or audit execution failure |

### Profiles

| Profile | Behavior |
|---|---|
| `ci` | Default. Static repository and dependency checks without assuming a runtime `.env` exists |
| `production` | Adds effective Laravel configuration and deployment filesystem checks |
| `local` | Static checks suitable for a developer workstation |

CI environment variables do not disable production checks. Use `--profile=production` when the pipeline has loaded the intended deployment configuration.

### Built-in audits

- `supply-chain`: lockfile presence/synchronization, secure Composer repositories, plugin allow-listing, and JavaScript lockfile support
- `composer`: Composer advisories, malware, and abandoned production packages from `composer.lock`
- `npm`: npm advisories from `package-lock.json`, auto-detected without a flag
- `laravel-config`: tracked `.env` detection and production application/session/tooling rules
- `platform`: offline PHP and Laravel support-window enforcement, including Composer's exact platform target
- `source`: parser-backed PHP taint analysis, Blade review, and redacted credential detection
- `storage`: production-only operational warnings; these do not fail the security gate

Yarn, pnpm, and Bun lockfiles are detected but are not yet parsed. Warden reports the limitation so the package-manager-native audit can be added as a separate CI step.

### Source security model

Warden parses each selected PHP file once and distinguishes enforcement from review guidance:

- Blocking rules require a high-confidence condition such as request-controlled data reaching a command, raw output, outbound URL, redirect, deserializer, or filesystem sink. Other blocking rules cover interpolated raw SQL, disabled TLS verification, provider-format credentials, weak constant ciphers, and explicit CSRF middleware removal.
- Advisory rules highlight unescaped Blade output, forms without an obvious CSRF directive, mass-assignment disabling, debug calls, sensitive logging, weak contextual hashing/randomness, and secret-like literals.

Credentials are never copied into reports. Warden emits only the provider, location, and a redacted description; the secret contributes only a one-way hash to the stable fingerprint.

Default PHP scan paths are `app`, `bootstrap`, `config`, and `routes`; Blade templates are read from `resources/views`. File paths, exclusions, and the 1 MiB file limit are configurable under `warden.audits.source`. A selected file that cannot be read or parsed makes the scan incomplete and exits `2`.

### Rule policy

Every configurable rule has a stable ID and a built-in disposition. Override one without suppressing individual occurrences:

```php
'rule_overrides' => [
    'source.blade.unescaped-output' => 'enforced',
    'source.php.debug-call' => 'off',
],
```

Allowed values are `enforced`, `advisory`, and `off`. Unknown rule IDs and invalid values are configuration errors. Advisory findings remain visible in every report but do not affect exit `1`; suppressions and baselines still apply to them.

See the complete [rule catalogue](docs/rules.md) for stable IDs, default dispositions, and rationale.

### Supply-chain review window

Composer packages released within three days produce an advisory. A recent package becomes a blocking critical finding when it is a Composer plugin or registers `autoload.files`, because it can execute automatically. The window is offline, uses `composer.lock` timestamps, respects `--scope`, and is configurable with `warden.audits.supply_chain.minimum_release_age_days`.

## Reviewed suppressions

Suppressions are exact, documented, and expiring. Wildcards are not supported.

```php
'ignore_findings' => [
    [
        'id' => 'composer.advisory.ghsa-example',
        'fingerprint' => 'optional-fingerprint-for-one-occurrence',
        'reason' => 'Compensating control reviewed in SEC-123',
        'expires_at' => '2099-12-31',
    ],
],
```

An expired or malformed suppression is a configuration error and exits `2`.

## Baselines

Legacy applications can commit an explicit fingerprint baseline while continuing to fail on new findings:

```bash
php artisan warden:baseline \
  --reason="Existing findings tracked in SEC-123" \
  --expires=2099-12-31
```

This creates `warden-baseline.json`. Baseline generation refuses to write a file if any audit is incomplete.

## Reports

Warden supports:

- `console`: readable terminal report
- `json`: versioned Warden schema with audits, blocking/advisory counts, findings, ignored findings, errors, and summary; the schema ships at `resources/schemas/warden-report-2.0.0.json`
- `github`: GitHub Actions workflow annotations
- `gitlab`: GitLab dependency scanning report schema 15.2.4
- `sarif`: SARIF 2.1.0 for GitHub code scanning and compatible platforms
- `junit`: portable JUnit XML for Jenkins and other CI systems

Advisory findings render as notices in GitHub and skipped tests in JUnit. SARIF and JSON preserve the `blocking` property.

`--output-file=-` writes to stdout. Relative file paths are resolved from the Laravel application root.

## Notifications

Notifications are opt-in and never affect the audit exit code:

```bash
php artisan warden:audit --notify
```

Configure any combination of:

```env
WARDEN_SLACK_WEBHOOK_URL=
WARDEN_DISCORD_WEBHOOK_URL=
WARDEN_TEAMS_WEBHOOK_URL=
WARDEN_EMAIL_RECIPIENTS=security@example.com
WARDEN_EMAIL_FROM=warden@example.com
```

Each channel is dispatched once. Delivery failures are written to stderr after the report is produced.

## Custom audits

Custom audits receive the immutable audit context and return a typed result:

```php
use Dgtlss\Warden\Contracts\CustomAudit;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;

final class PublicBucketAudit implements CustomAudit
{
    public function getName(): string { return 'public-bucket'; }
    public function getDescription(): string { return 'Checks the effective filesystem configuration.'; }
    public function shouldRun(AuditContext $context): bool { return $context->profile === 'production'; }

    public function run(AuditContext $context): AuditResult
    {
        $findings = config('filesystems.disks.s3.visibility') === 'public'
            ? [new Finding(
                id: 'custom.storage.public',
                source: $this->getName(),
                title: 'S3 disk is public',
                severity: Severity::High,
                description: 'The default S3 disk visibility is public.',
                remediation: 'Set the disk visibility to private.',
                path: 'config/filesystems.php',
            )]
            : [];

        return AuditResult::complete($this->getName(), $findings);
    }
}
```

Register the class in `config/warden.php` under `custom_audits`.

## Development

```bash
composer install
composer test
composer phpstan
composer rector
composer validate --strict
```

See [contributing.md](contributing.md) for contribution guidelines.

Upgrading from Warden 1.x? Read [UPGRADE.md](UPGRADE.md) before changing the dependency constraint.

## License

Warden is released under the [MIT License](LICENSE).
