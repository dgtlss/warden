<?php

namespace Dgtlss\Warden\Jobs;

use Dgtlss\Warden\Contracts\AuditService;
use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\Notifications\Channels\DiscordChannel;
use Dgtlss\Warden\Notifications\Channels\EmailChannel;
use Dgtlss\Warden\Notifications\Channels\SlackChannel;
use Dgtlss\Warden\Notifications\Channels\TeamsChannel;
use Dgtlss\Warden\Services\AuditCacheService;
use Dgtlss\Warden\Services\AuditHistoryService;
use Dgtlss\Warden\Services\Audits\ComposerAuditService;
use Dgtlss\Warden\Services\Audits\DebugModeAuditService;
use Dgtlss\Warden\Services\Audits\EnvAuditService;
use Dgtlss\Warden\Services\Audits\NpmAuditService;
use Dgtlss\Warden\Services\Audits\StorageAuditService;
use Dgtlss\Warden\Services\ParallelAuditExecutor;
use Dgtlss\Warden\Services\RemediationService;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

/**
 * Job for running security audits in the background.
 */
class RunSecurityAuditJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    /**
     * The number of times the job may be attempted.
     */
    public int $tries = 3;

    /**
     * The number of seconds the job can run before timing out.
     */
    public int $timeout = 300;

    /**
     * @param array<int, string> $auditTypes The types of audits to run (composer, npm, env, storage, debug)
     * @param string|null $severity Minimum severity level to report
     * @param bool $notify Whether to send notifications
     * @param bool $forceRefresh Whether to force cache refresh
     * @param bool $includeRemediation Whether to include remediation suggestions
     */
    public function __construct(
        public array $auditTypes = [],
        public ?string $severity = null,
        public bool $notify = true,
        public bool $forceRefresh = false,
        public bool $includeRemediation = true,
    ) {
        if (empty($this->auditTypes)) {
            $this->auditTypes = ['composer', 'env', 'storage', 'debug'];
        }
    }

    /**
     * Execute the job.
     */
    public function handle(
        AuditCacheService $cacheService,
        ParallelAuditExecutor $parallelExecutor,
        RemediationService $remediationService,
    ): void {
        Log::info('Warden: Starting background security audit', [
            'audit_types' => $this->auditTypes,
            'severity' => $this->severity,
            'notify' => $this->notify,
        ]);

        if ($this->forceRefresh) {
            $cacheService->clearCache();
        }

        $auditServices = $this->initializeAuditServices();

        foreach ($auditServices as $auditService) {
            $parallelExecutor->addAudit($auditService);
        }

        $results = $parallelExecutor->execute(true);

        /** @var array<int, Finding> $allFindings */
        $allFindings = [];
        $hasFailures = false;

        foreach ($results as $result) {
            if (!$result['success']) {
                Log::warning('Warden: Audit failed', ['service' => $result['service']]);
                $hasFailures = true;
                continue;
            }

            $service = $result['service'];
            $allFindings = array_merge($allFindings, $service->getFindings());
        }

        if ($this->severity !== null) {
            $allFindings = $this->filterBySeverity($allFindings, $this->severity);
        }

        if ($this->includeRemediation && !empty($allFindings)) {
            $allFindings = $remediationService->enrichFindings($allFindings);
        }

        Log::info('Warden: Audit completed', [
            'findings_count' => count($allFindings),
            'has_failures' => $hasFailures,
        ]);

        $this->storeAuditHistory($allFindings);

        if ($this->notify && !empty($allFindings)) {
            $this->sendNotifications($allFindings);
        }
    }

    /**
     * Initialize the audit services based on configuration.
     *
     * @return array<int, AuditService>
     */
    protected function initializeAuditServices(): array
    {
        $services = [];

        foreach ($this->auditTypes as $type) {
            $service = match (strtolower($type)) {
                'composer' => new ComposerAuditService(),
                'npm' => new NpmAuditService(),
                'env' => new EnvAuditService(),
                'storage' => new StorageAuditService(),
                'debug' => new DebugModeAuditService(),
                default => null,
            };

            if ($service !== null) {
                $services[] = $service;
            }
        }

        return $services;
    }

    /**
     * Filter findings by severity level.
     *
     * @param array<int, Finding> $findings
     * @return array<int, Finding>
     */
    protected function filterBySeverity(array $findings, string $minSeverity): array
    {
        $severityOrder = ['low' => 1, 'medium' => 2, 'moderate' => 2, 'high' => 3, 'critical' => 4];
        $minLevel = $severityOrder[strtolower($minSeverity)] ?? 1;

        return array_filter($findings, function (Finding $finding) use ($severityOrder, $minLevel) {
            $findingLevel = $severityOrder[strtolower($finding->severity->value)] ?? 1;

            return $findingLevel >= $minLevel;
        });
    }

    /**
     * Store the audit results in history.
     *
     * @param array<int, Finding> $findings
     */
    protected function storeAuditHistory(array $findings): void
    {
        /** @var bool $historyEnabled */
        $historyEnabled = config('warden.history.enabled', false);

        if (!$historyEnabled) {
            return;
        }

        try {
            $historyService = app(AuditHistoryService::class);
            $historyService->store(
                auditType: 'background_job',
                findings: $findings,
                metadata: ['job_class' => self::class],
                trigger: 'queue',
            );
        } catch (\Exception $e) {
            Log::error('Warden: Failed to store audit history', ['error' => $e->getMessage()]);
        }
    }

    /**
     * Send notifications for the findings.
     *
     * @param array<int, Finding> $findings
     */
    protected function sendNotifications(array $findings): void
    {
        $channels = $this->getConfiguredChannels();

        foreach ($channels as $channel) {
            try {
                $channel->send($findings);
                Log::info('Warden: Notification sent', ['channel' => get_class($channel)]);
            } catch (\Exception $e) {
                Log::error('Warden: Failed to send notification', [
                    'channel' => get_class($channel),
                    'error' => $e->getMessage(),
                ]);
            }
        }
    }

    /**
     * Get the configured notification channels.
     *
     * @return array<int, NotificationChannel>
     */
    protected function getConfiguredChannels(): array
    {
        $channels = [];

        /** @var string|null $slackWebhook */
        $slackWebhook = config('warden.notifications.slack.webhook_url');
        if ($slackWebhook !== null && $slackWebhook !== '') {
            $channels[] = new SlackChannel();
        }

        /** @var string|null $discordWebhook */
        $discordWebhook = config('warden.notifications.discord.webhook_url');
        if ($discordWebhook !== null && $discordWebhook !== '') {
            $channels[] = new DiscordChannel();
        }

        /** @var string|null $teamsWebhook */
        $teamsWebhook = config('warden.notifications.teams.webhook_url');
        if ($teamsWebhook !== null && $teamsWebhook !== '') {
            $channels[] = new TeamsChannel();
        }

        /** @var array<int, string>|null $emailRecipients */
        $emailRecipients = config('warden.notifications.email.recipients');
        if ($emailRecipients !== null && !empty($emailRecipients)) {
            $channels[] = new EmailChannel();
        }

        return $channels;
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error('Warden: Background audit job failed', [
            'error' => $exception->getMessage(),
            'audit_types' => $this->auditTypes,
        ]);
    }
}
