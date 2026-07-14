<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Commands;

use Illuminate\Console\Command;

final class WardenInitCommand extends Command
{
    protected $signature = 'warden:init
        {--ci=none : CI configuration to generate (github|gitlab|both|none)}
        {--force : Replace only Warden-owned generated CI files}';

    protected $description = 'Publish Warden configuration and safely generate dedicated CI integration files.';

    public function handle(): int
    {
        $ci = strtolower((string) $this->option('ci'));
        if (!in_array($ci, ['github', 'gitlab', 'both', 'none'], true)) {
            $this->error('Invalid --ci value. Expected github, gitlab, both, or none.');

            return Command::FAILURE;
        }

        if (!$this->publishConfiguration()) {
            return Command::FAILURE;
        }

        $targets = $ci === 'both' ? ['github', 'gitlab'] : ($ci === 'none' ? [] : [$ci]);
        foreach ($targets as $target) {
            if (!$this->{'generate' . ucfirst($target)}()) {
                return Command::FAILURE;
            }
        }

        $this->info('Warden initialization complete.');

        return Command::SUCCESS;
    }

    private function publishConfiguration(): bool
    {
        $target = config_path('warden.php');
        if (is_link($target)) {
            $this->error('Refusing to write config/warden.php through a symbolic link.');

            return false;
        }

        if (is_file($target)) {
            $this->line('Preserved existing config/warden.php.');

            return true;
        }

        if (!is_dir(dirname($target)) && !mkdir(dirname($target), 0755, true) && !is_dir(dirname($target))) {
            $this->error('Unable to create the application config directory.');

            return false;
        }

        if (!copy(__DIR__ . '/../config/warden.php', $target)) {
            $this->error('Unable to publish config/warden.php.');

            return false;
        }

        $this->info('Created config/warden.php.');

        return true;
    }

    private function generateGithub(): bool
    {
        $target = base_path('.github/workflows/warden.yml');
        $contents = $this->stub('github-workflow.yml');
        if ($contents === null) {
            $this->error('Unable to read bundled stub github-workflow.yml.');

            return false;
        }

        return $this->writeOwnedFile($target, $contents, '.github/workflows/warden.yml');
    }

    private function generateGitlab(): bool
    {
        $target = base_path('.gitlab/warden.yml');
        $contents = $this->stub('gitlab-ci.yml');
        if ($contents === null) {
            $this->error('Unable to read bundled stub gitlab-ci.yml.');

            return false;
        }

        if (!$this->writeOwnedFile($target, $contents, '.gitlab/warden.yml')) {
            return false;
        }

        $root = base_path('.gitlab-ci.yml');
        if (is_link($root)) {
            $this->error('Refusing to write .gitlab-ci.yml through a symbolic link.');

            return false;
        }

        if (!is_file($root)) {
            if (file_put_contents($root, "include:\n  - local: .gitlab/warden.yml\n") === false) {
                $this->error('Unable to create .gitlab-ci.yml.');

                return false;
            }

            $this->info('Created .gitlab-ci.yml with the Warden include.');
        } else {
            $this->line('Existing .gitlab-ci.yml was preserved. Add: include: [{ local: .gitlab/warden.yml }]');
        }

        return true;
    }

    private function writeOwnedFile(string $target, string $contents, string $display): bool
    {
        if (is_link($target)) {
            $this->error(sprintf('Refusing to write %s through a symbolic link.', $display));

            return false;
        }

        if (is_file($target) && !(bool) $this->option('force')) {
            $this->error(sprintf('%s already exists; pass --force to replace this Warden-owned file.', $display));

            return false;
        }

        if (!is_dir(dirname($target)) && !mkdir(dirname($target), 0755, true) && !is_dir(dirname($target))) {
            $this->error(sprintf('Unable to create the directory for %s.', $display));

            return false;
        }

        if (file_put_contents($target, $contents) === false) {
            $this->error(sprintf('Unable to write %s.', $display));

            return false;
        }

        $this->info(sprintf('Created %s.', $display));

        return true;
    }

    private function stub(string $name): ?string
    {
        $contents = @file_get_contents(__DIR__ . '/../stubs/' . $name);
        if (!is_string($contents)) {
            return null;
        }

        return str_replace('{{PHP_VERSION}}', PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION, $contents);
    }
}
