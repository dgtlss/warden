<?php

namespace Dgtlss\Warden\Commands;

use Dgtlss\Warden\Services\AuditHistoryService;
use Dgtlss\Warden\Services\AuditManager;
use Dgtlss\Warden\Services\CloudSyncService;
use Illuminate\Console\Command;
use Symfony\Component\Process\Process;
use function Laravel\Prompts\table;

class WardenDoctorCommand extends Command
{
    protected $signature = 'warden:doctor';

    protected $description = 'Validate Warden prerequisites and integration readiness.';

    public function __construct(
        protected AuditManager $auditManager,
        protected AuditHistoryService $historyService,
        protected CloudSyncService $cloudSyncService,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        $checks = [
            ['Active profile', $this->auditManager->resolveProfile(), 'ok'],
            ['Composer available', $this->binaryExists('composer') ? 'Yes' : 'No', $this->binaryExists('composer') ? 'ok' : 'fail'],
            ['Node package manager', $this->detectNodePackageManager(), $this->detectNodePackageManager() === 'Missing' ? 'warn' : 'ok'],
            ['History persistence', $this->historyService->canPersist() ? 'Ready' : ($this->historyService->isEnabled() ? 'Configured but table missing' : 'Disabled'), $this->historyService->canPersist() ? 'ok' : ($this->historyService->isEnabled() ? 'warn' : 'ok')],
            ['Cloud sync', $this->cloudSyncService->isConfigured() ? 'Ready' : ($this->cloudSyncService->isEnabled() ? 'Enabled but incomplete' : 'Disabled'), $this->cloudSyncService->isConfigured() ? 'ok' : ($this->cloudSyncService->isEnabled() ? 'warn' : 'ok')],
            ['Slack webhook', config('warden.notifications.slack.webhook_url') ? 'Configured' : 'Not configured', config('warden.notifications.slack.webhook_url') ? 'ok' : 'warn'],
            ['Discord webhook', config('warden.notifications.discord.webhook_url') ? 'Configured' : 'Not configured', config('warden.notifications.discord.webhook_url') ? 'ok' : 'warn'],
            ['Teams webhook', config('warden.notifications.teams.webhook_url') ? 'Configured' : 'Not configured', config('warden.notifications.teams.webhook_url') ? 'ok' : 'warn'],
            ['Email recipients', config('warden.notifications.email.recipients') ? 'Configured' : 'Not configured', config('warden.notifications.email.recipients') ? 'ok' : 'warn'],
        ];

        $rows = array_map(static function (array $check): array {
            return [
                $check[0],
                $check[1],
                match ($check[2]) {
                    'fail' => '✗',
                    'warn' => '!',
                    default => '✓',
                },
            ];
        }, $checks);

        table(['Check', 'Status', 'Result'], $rows);

        return collect($checks)->contains(static fn (array $check): bool => $check[2] === 'fail') ? 1 : 0;
    }

    protected function binaryExists(string $binary): bool
    {
        $process = new Process(['which', $binary]);
        $process->run();

        return $process->isSuccessful();
    }

    protected function detectNodePackageManager(): string
    {
        if (file_exists(base_path('pnpm-lock.yaml')) && $this->binaryExists('pnpm')) {
            return 'pnpm';
        }

        if (file_exists(base_path('yarn.lock')) && $this->binaryExists('yarn')) {
            return 'yarn';
        }

        if (file_exists(base_path('package-lock.json')) && $this->binaryExists('npm')) {
            return 'npm';
        }

        if (file_exists(base_path('package.json'))) {
            return 'Missing';
        }

        return 'Not needed';
    }
}
