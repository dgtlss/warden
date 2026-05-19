<?php

namespace Dgtlss\Warden\Commands;

use Dgtlss\Warden\Services\AuditHistoryService;
use Dgtlss\Warden\Services\CloudSyncService;
use Illuminate\Console\Command;

class WardenSyncCommand extends Command
{
    protected $signature = 'warden:sync';

    protected $description = 'Sync the most recent Warden audit run to Warden Cloud.';

    public function __construct(
        protected AuditHistoryService $historyService,
        protected CloudSyncService $cloudSyncService,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        if (!$this->cloudSyncService->isEnabled()) {
            $this->warn('Warden Cloud sync is disabled.');
            return 1;
        }

        if (!$this->cloudSyncService->isConfigured()) {
            $this->warn('Warden Cloud sync is enabled but not fully configured.');
            return 1;
        }

        $latest = $this->historyService->latest(1);
        if ($latest === []) {
            $this->warn('No audit history entries are available to sync. Run warden:audit first.');
            return 1;
        }

        $payload = $latest[0];
        $synced = $this->cloudSyncService->sync($payload);

        if ($synced) {
            $this->info('Latest audit run synced to Warden Cloud.');
            return 0;
        }

        $this->warn('Warden Cloud sync did not complete.');
        return 1;
    }
}
