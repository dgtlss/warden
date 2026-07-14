<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Commands;

use Dgtlss\Warden\Services\Audits\PhpSyntaxAuditService;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Illuminate\Console\Command;

final class WardenSyntaxCommand extends Command
{
    protected $signature = 'warden:syntax';

    protected $description = 'Check every application PHP file for syntax errors.';

    public function __construct(private readonly PhpSyntaxAuditService $phpSyntaxAuditService)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $auditResult = $this->phpSyntaxAuditService->run(new AuditContext(profile: 'ci', scope: 'all'));
        foreach ($auditResult->findings as $finding) {
            $this->error(sprintf('%s: %s', $finding->path ?? 'unknown', $finding->description));
        }

        if ($auditResult->errors !== []) {
            foreach ($auditResult->errors as $error) {
                $this->error(sprintf('%s: %s', $error->code, $error->message));
            }

            return 2;
        }

        if ($auditResult->findings !== []) {
            return 1;
        }

        $this->info('No PHP syntax errors found.');

        return 0;
    }
}
