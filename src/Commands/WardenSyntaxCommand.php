<?php

namespace Dgtlss\Warden\Commands;

use Illuminate\Console\Command;
use Dgtlss\Warden\Services\Audits\PhpSyntaxAuditService;
use Dgtlss\Warden\ValueObjects\Finding;
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

        $phpSyntaxAuditService = new PhpSyntaxAuditService();

        /** @var bool $result */
        $result = spin(
            fn() => $phpSyntaxAuditService->run(),
            'Running PHP syntax check...'
        );

        if ($result) {
            info('✅ No PHP syntax errors found.');
            return 0;
        }

        $findings = $phpSyntaxAuditService->getFindings();
        $this->displayFindings($findings);

        // Check if the audit itself failed to run.
        if (collect($findings)->contains(fn(Finding $f) => $f->severity->value === 'error')) {
            return 2;
        }

        return 1;
    }

    /**
     * @param array<int, Finding> $findings
     */
    protected function displayFindings(array $findings): void
    {
        $this->error(count($findings) . ' syntax errors found.');

        $headers = ['File', 'Error Description'];
        /** @var array<int, array<int, string>> $rows */
        $rows = [];

        foreach ($findings as $finding) {
            $rows[] = [
                $finding->title,
                is_string($finding->error) ? $finding->error : 'Unknown error',
            ];
        }

        table(
            headers: $headers,
            rows: $rows
        );
    }
}
