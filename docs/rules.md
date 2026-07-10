# Warden rule catalogue

Every rule has a stable ID and a default disposition. `enforced` findings participate in `--fail-on`; `advisory` findings are reported without changing the security exit code. Any rule in this table may be changed to `enforced`, `advisory`, or `off` through `warden.rule_overrides`.

## Source rules

| Rule ID | Default | Purpose |
|---|---|---|
| `source.secrets.provider-credential` | enforced | Recognizable provider credentials and private-key headers |
| `source.secrets.suspicious-literal` | advisory | Literal values assigned to secret-named keys or variables |
| `source.php.sql-dynamic-raw` | enforced | Interpolation, concatenation, or dynamic formatting in Laravel raw SQL |
| `source.php.command-tainted-input` | enforced | Request input reaching shell execution functions |
| `source.php.unsafe-deserialization` | enforced | Request input reaching unrestricted `unserialize()` |
| `source.php.ssrf-tainted-url` | enforced | Request input selecting an HTTP client or cURL destination |
| `source.php.path-traversal` | enforced | Request input reaching include, filesystem, or Storage paths |
| `source.php.open-redirect` | enforced | Request input selecting an external redirect or Location header |
| `source.php.xss-tainted-output` | enforced | Request input reaching raw PHP output without recognized escaping |
| `source.php.tls-verification-disabled` | enforced | Laravel, Guzzle, cURL, or stream TLS verification disabled |
| `source.php.weak-cipher` | enforced | Deprecated or unsuitable constant cipher selection |
| `source.laravel.csrf-disabled` | enforced | Explicit removal of Laravel request-forgery middleware |
| `source.blade.unescaped-output` | advisory | Blade `{!! !!}` output requiring trust review |
| `source.blade.form-missing-csrf` | advisory | Mutable non-Livewire form without an obvious CSRF directive |
| `source.laravel.mass-assignment-disabled` | advisory | `$guarded = []` or global `Model::unguard()` |
| `source.php.debug-call` | advisory | Debug/output functions left in application source |
| `source.php.sensitive-log` | advisory | Secret-named or request data referenced by logging code |
| `source.php.weak-hash-context` | advisory | MD5 or SHA-1 appearing in a security-named context |
| `source.php.insecure-rng-context` | advisory | Predictable randomness appearing in a security-named context |

## Configuration, platform, and supply-chain rules

| Rule ID | Default | Purpose |
|---|---|---|
| `laravel.cors.wildcard-credentials` | enforced | Wildcard CORS combined with credentials |
| `laravel.cors.wildcard-origin` | advisory | Wildcard CORS without credentials |
| `laravel.debug-tool.enabled` | enforced | Telescope, Debugbar, or Clockwork enabled in production |
| `deployment.env.permissions` | advisory | World-readable or world-writable production `.env` |
| `deployment.path.world-writable` | advisory | World-writable Laravel runtime path |
| `platform.php.eol` | enforced | Unsupported PHP branch |
| `platform.php.security-only` | advisory | PHP in security-only or near-EOL support |
| `platform.laravel.eol` | enforced | Unsupported Laravel major |
| `platform.laravel.security-only` | advisory | Laravel in security-only or near-EOL support |
| `supply-chain.composer.recent-package` | advisory | Package inside the configured release-age window |
| `supply-chain.composer.recent-executable-package` | enforced | Recent package using Composer plugins or `autoload.files` |
| `supply-chain.composer.release-time-missing` | advisory | Package whose release age cannot be evaluated offline |