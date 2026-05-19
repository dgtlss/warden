<?php

namespace Dgtlss\Warden\Commands;

use Dgtlss\Warden\Services\AuditHistoryService;
use Illuminate\Console\Command;
use function Laravel\Prompts\table;

class WardenHistoryCommand extends Command
{
    protected $signature = 'warden:history {--limit=10 : Number of audit runs to display}';

    protected $description = 'Show recent Warden audit history entries.';

    public function __construct(protected AuditHistoryService $historyService)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        if (!$this->historyService->isEnabled()) {
            $this->warn('Audit history is disabled. Enable warden.history.enabled to persist run history.');
            return 1;
        }

        if (!$this->historyService->canPersist()) {
            $this->warn('Audit history is enabled, but the history table is not available.');
            return 1;
        }

        $entries = $this->historyService->latest((int) $this->option('limit'));
        if ($entries === []) {
            $this->info('No Warden audit history entries were found.');
            return 0;
        }

        $rows = array_map(static fn (array $entry): array => [
            $entry['id'],
            $entry['created_at'],
            $entry['trigger'],
            $entry['total_findings'],
            $entry['critical_findings'],
            $entry['high_findings'],
            $entry['duration_ms'] . 'ms',
        ], $entries);

        table(['ID', 'Created', 'Trigger', 'Findings', 'Critical', 'High', 'Duration'], $rows);

        return 0;
    }
}
