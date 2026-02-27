# AGENTS.md

## Cursor Cloud specific instructions

### Project overview

Warden is a Laravel security audit **package** (library), not a standalone application. It is tested using Orchestra Testbench which bootstraps a minimal Laravel environment in-memory.

### Prerequisites (installed in VM snapshot)

- PHP 8.4 (from `ppa:ondrej/php`; extensions: cli, mbstring, xml, curl, zip, sqlite3)
- Composer 2.x (installed to `/usr/local/bin/composer`)

### Key commands

| Task | Command |
|---|---|
| Install dependencies | `composer install --no-interaction` |
| Static analysis (lint) | `composer phpstan` or `vendor/bin/phpstan analyse --memory-limit=2G` |
| Run tests | `vendor/bin/phpunit tests/` |
| Code quality (dry-run) | `vendor/bin/rector process --dry-run` |
| Run package commands | `vendor/bin/testbench warden:audit` / `vendor/bin/testbench warden:syntax` |

### Gotchas

- **PHPStan error with full framework**: When `orchestra/testbench` is installed (which brings in `laravel/framework`), PHPStan reports 1 error in `DebugModeAuditService.php` line 113 (`RouteCollectionInterface` not iterable). This error does not appear in CI because CI installs without testbench. This is a pre-existing code issue, not an environment problem.
- **Test failures are pre-existing**: All 5 tests in `tests/` currently fail due to mock expectations not matching the actual implementation (e.g., `ParallelAuditExecutor::addAudit()` is called but not mocked). These are not caused by the environment setup.
- **testbench.yaml**: A `testbench.yaml` file at the repo root registers `WardenServiceProvider` so that `vendor/bin/testbench` can run the package's artisan commands (e.g., `warden:audit`).
- **No phpunit.xml**: The repo does not include a `phpunit.xml`. Tests are run directly with `vendor/bin/phpunit tests/`.
