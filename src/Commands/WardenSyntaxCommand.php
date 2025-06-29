<?php

namespace Dgtlss\Warden\Commands;

use Illuminate\Console\Command;
use Dgtlss\Warden\Services\Audits\PhpSyntaxAuditService;
use function Laravel\Prompts\info;
use function Laravel\Prompts\table;
use function Laravel\Prompts\spin;

class WardenSyntaxCommand extends Command
{
    protected $signature = 'warden:syntax';
    protected $description = 'Performs a PHP syntax audit on your application code.';

    public function handle(): int
    {
        $this->info('Warden PHP Syntax Audit');
        
        $auditService = new PhpSyntaxAuditService();

        $result = spin(
            fn() => $auditService->run(),
            'Running PHP syntax check...'
        );

        if ($result) {
            info('✅ No PHP syntax errors found.');
            return 0;
        }

        $findings = $auditService->getFindings();
        $this->displayFindings($findings);

        // Check if the audit itself failed to run.
        if (collect($findings)->contains('severity', 'error')) {
            return 2;
        }

        return 1;
    }

    protected function displayFindings(array $findings): void
    {
        $this->error(count($findings) . ' syntax errors found.');
        
        $headers = ['File', 'Error Description'];
        $rows = [];

        foreach ($findings as $finding) {
            $rows[] = [
                $finding['title'],
                $finding['description'],
            ];
        }

        table(
            headers: $headers,
            rows: $rows
        );
    }
} 