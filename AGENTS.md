# AGENTS.md

## Cursor Cloud-specific instructions

### Project overview

Warden is a Laravel security audit **package** (library), not a standalone application. It is tested using Orchestra Testbench, which bootstraps a minimal Laravel environment in-memory.

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

- **Tests target Laravel 12+**: The package supports Laravel 7–12, but `orchestra/testbench ^10.9` pins the test suite to Laravel 12+; CI runs against the latest supported Laravel.
- **PHPStan with full framework**: When `orchestra/testbench` is installed (which brings in `laravel/framework`), PHPStan may report additional errors due to full type information replacing stubs. The CI workflow installs testbench, so check PHPStan passes with `composer phpstan`.
- **testbench.yaml**: Registers `WardenServiceProvider` so `vendor/bin/testbench` can run the package's artisan commands (e.g., `warden:audit`).
- **Test app**: To test the package inside a real Laravel app, create one in `/tmp`: `cd /tmp && composer create-project laravel/laravel warden-test-app` then `cd warden-test-app && composer config repositories.warden path /workspace && composer require dgtlss/warden:* --dev`.
