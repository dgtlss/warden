<?php

namespace Dgtlss\Warden\Commands;

use Dgtlss\Warden\Services\AuditManager;
use Dgtlss\Warden\Services\BaselineService;
use Illuminate\Console\Command;

class WardenBaselineCommand extends Command
{
    protected $signature = 'warden:baseline
        {--path= : Custom baseline file path}
        {--reason= : Reason applied to each generated baseline entry}
        {--expires= : Optional expiry timestamp for generated entries}
        {--npm : Include JavaScript dependency auditing}
        {--force : Ignore cached audit results while generating the baseline}';

    protected $description = 'Generate or refresh the Warden baseline suppression file.';

    public function __construct(
        protected AuditManager $auditManager,
        protected BaselineService $baselineService,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        $report = $this->auditManager->run(
            includeJavascript: (bool) $this->option('npm'),
            force: (bool) $this->option('force'),
        );

        if ($report->findings === []) {
            $this->info('No active findings were detected, so no baseline file was written.');
            return 0;
        }

        $path = $this->baselineService->write(
            findings: $report->findings,
            path: $this->option('path') ? (string) $this->option('path') : null,
            reason: $this->option('reason') ? (string) $this->option('reason') : null,
            expiresAt: $this->option('expires') ? (string) $this->option('expires') : null,
        );

        $this->info(sprintf('Baseline written to %s with %d finding%s.', $path, count($report->findings), count($report->findings) === 1 ? '' : 's'));

        return 0;
    }
}
