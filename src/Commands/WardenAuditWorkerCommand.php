<?php

namespace Dgtlss\Warden\Commands;

use Dgtlss\Warden\Services\AuditRegistry;
use Illuminate\Console\Command;

class WardenAuditWorkerCommand extends Command
{
    protected $signature = 'warden:audit:worker
        {audit : The audit identifier to execute}
        {--profile=legacy : Profile used by the parent process}';

    protected $description = 'Execute a single Warden audit worker process.';

    protected $hidden = true;

    public function __construct(protected AuditRegistry $registry)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $auditId = (string) $this->argument('audit');
        $definition = $this->registry->definition($auditId, true);

        if ($definition === null) {
            $this->output->write(json_encode([
                'audit_id' => $auditId,
                'audit_name' => $auditId,
                'success' => false,
                'findings' => [[
                    'package' => $auditId,
                    'title' => 'Audit definition could not be resolved',
                    'rule_id' => 'warden.worker.audit-missing',
                    'category' => 'execution',
                    'severity' => 'high',
                    'description' => 'The requested audit identifier is not registered in this Warden installation.',
                ]],
                'metadata' => [],
            ], JSON_UNESCAPED_SLASHES));

            return 1;
        }

        $service = $definition->make();
        $success = $service->run();

        $this->output->write(json_encode([
            'audit_id' => $definition->id,
            'audit_name' => $definition->name,
            'success' => $success,
            'findings' => $service->getFindings(),
            'metadata' => method_exists($service, 'getMetadata') ? $service->getMetadata() : [],
        ], JSON_UNESCAPED_SLASHES));

        return $success ? 0 : 1;
    }
}
