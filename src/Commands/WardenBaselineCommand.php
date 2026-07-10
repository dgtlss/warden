<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Commands;

use Carbon\CarbonImmutable;
use Dgtlss\Warden\Services\AuditRunner;
use Dgtlss\Warden\Services\SuppressionService;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Illuminate\Console\Command;
use JsonException;
use Throwable;

final class WardenBaselineCommand extends Command
{
    protected $signature = 'warden:baseline
        {--profile=ci : Audit profile (ci|production|local)}
        {--scope=production : Dependency scope (production|all)}
        {--only= : Comma-separated audit IDs to run}
        {--skip= : Comma-separated audit IDs to skip}
        {--file= : Baseline path relative to the application root}
        {--reason= : Required review reason applied to every baseline entry}
        {--expires= : Required expiry date in YYYY-MM-DD format}';

    protected $description = 'Generate an explicit, expiring baseline from the current findings.';

    public function __construct(
        private readonly AuditRunner $auditRunner,
        private readonly SuppressionService $suppressionService,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        $profile = (string) $this->option('profile');
        $scope = (string) $this->option('scope');
        $reason = trim((string) $this->option('reason'));
        $expires = trim((string) $this->option('expires'));
        $file = trim((string) ($this->option('file') ?: config('warden.baseline.file', 'warden-baseline.json')));
        $only = $this->csvOption('only');
        $skip = $this->csvOption('skip');
        $timeout = config('warden.audits.timeout', 300);

        if (!in_array($profile, ['ci', 'production', 'local'], true) || !in_array($scope, ['production', 'all'], true)) {
            $this->error('Invalid profile or scope.');
            return 2;
        }

        if ($reason === '' || $expires === '') {
            $this->error('--reason and --expires are required.');
            return 2;
        }

        if ($file === '' || !is_int($timeout) || $timeout < 1 || $timeout > 3600) {
            $this->error('The baseline path and audit timeout must be valid.');
            return 2;
        }

        if (array_intersect($only, $skip) !== []) {
            $this->error('The same audit cannot be selected and skipped.');
            return 2;
        }

        if ($only !== [] || $skip !== []) {
            $available = $this->auditRunner->availableAuditIds();
            foreach ([...$only, ...$skip] as $audit) {
                if (!in_array($audit, $available, true)) {
                    $this->error(sprintf('Unknown audit "%s".', $audit));
                    return 2;
                }
            }
        }

        try {
            $expiry = CarbonImmutable::createFromFormat('!Y-m-d', $expires);
        } catch (Throwable) {
            $expiry = null;
        }

        if (!$expiry instanceof \Carbon\CarbonImmutable || $expiry->format('Y-m-d') !== $expires || $expiry->endOfDay()->isPast()) {
            $this->error('--expires must be a future date in YYYY-MM-DD format.');
            return 2;
        }

        $auditContext = new AuditContext(
            profile: $profile,
            scope: $scope,
            timeout: $timeout,
            only: $only,
            skip: $skip,
            scannedAt: CarbonImmutable::now(),
        );
        $suppressionErrors = $this->suppressionService->errors(includeBaseline: false);
        if ($suppressionErrors !== []) {
            foreach ($suppressionErrors as $suppressionError) {
                $this->error(sprintf('[%s:%s] %s', $suppressionError->audit, $suppressionError->code, $suppressionError->message));
            }

            return 2;
        }

        $auditReport = $this->suppressionService->apply($this->auditRunner->run($auditContext), includeBaseline: false);
        if ($auditReport->errors() !== []) {
            foreach ($auditReport->errors() as $error) {
                $this->error(sprintf('[%s:%s] %s', $error->audit, $error->code, $error->message));
            }

            return 2;
        }

        $entries = array_map(static fn ($finding): array => [
            'id' => $finding->id,
            'fingerprint' => $finding->fingerprint(),
            'reason' => $reason,
            'expires_at' => $expires,
        ], $auditReport->findings());

        $payload = [
            'schema_version' => '1.0.0',
            'generated_at' => CarbonImmutable::now()->toISOString(),
            'profile' => $profile,
            'scope' => $scope,
            'findings' => $entries,
        ];

        try {
            $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL;
        } catch (JsonException $jsonException) {
            $this->error($jsonException->getMessage());
            return 2;
        }

        $path = str_starts_with($file, DIRECTORY_SEPARATOR) ? $file : base_path($file);
        if (@file_put_contents($path, $json) === false) {
            $this->error(sprintf('Unable to write baseline to %s.', $file));
            return 2;
        }

        $this->info(sprintf('Wrote %d baseline finding(s) to %s.', count($entries), $file));

        return 0;
    }

    /** @return list<string> */
    private function csvOption(string $name): array
    {
        $value = $this->option($name);
        if (!is_string($value) || trim($value) === '') {
            return [];
        }

        $items = array_values(array_unique(array_filter(
            array_map('trim', explode(',', $value)),
            static fn (string $item): bool => $item !== '',
        )));
        sort($items);

        return $items;
    }
}
