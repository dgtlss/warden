<?php

namespace Dgtlss\Warden\Commands;

use Dgtlss\Warden\Services\AuditHistoryService;
use Illuminate\Console\Command;

class WardenHistoryPruneCommand extends Command
{
    protected $signature = 'warden:history:prune {--days= : Override the configured retention window in days}';

    protected $description = 'Delete old Warden audit history entries.';

    public function __construct(protected AuditHistoryService $historyService)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        if (!$this->historyService->canPersist()) {
            $this->warn('Audit history is not available for pruning.');
            return 1;
        }

        $deleted = $this->historyService->prune($this->option('days') ? (int) $this->option('days') : null);
        $this->info(sprintf('Pruned %d audit history entr%s.', $deleted, $deleted === 1 ? 'y' : 'ies'));

        return 0;
    }
}
