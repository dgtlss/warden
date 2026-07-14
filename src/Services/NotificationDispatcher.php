<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\Notifications\Channels\DiscordChannel;
use Dgtlss\Warden\Notifications\Channels\EmailChannel;
use Dgtlss\Warden\Notifications\Channels\SlackChannel;
use Dgtlss\Warden\Notifications\Channels\TeamsChannel;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Dgtlss\Warden\ValueObjects\Finding;
use Throwable;

final class NotificationDispatcher
{
    /** @return list<string> Non-gating delivery warnings. */
    public function send(AuditReport $auditReport): array
    {
        $warnings = [];
        foreach ($this->channels() as $notificationChannel) {
            if (!$notificationChannel->isConfigured()) {
                continue;
            }

            try {
                $notificationChannel->send(array_map(
                    static fn (Finding $finding): array => [
                        'id' => $finding->id,
                        'fingerprint' => $finding->fingerprint(),
                        'source' => $finding->source,
                        'package' => $finding->package ?? 'application',
                        'title' => $finding->title,
                        'severity' => $finding->severity->value,
                        'description' => $finding->description,
                        'remediation' => $finding->remediation,
                        'cve' => $finding->reference,
                        'affected_versions' => $finding->metadata['affected_versions'] ?? null,
                    ],
                    $auditReport->findings(),
                ));
            } catch (Throwable $throwable) {
                $warnings[] = sprintf('%s notification failed: %s', $notificationChannel->getName(), $throwable->getMessage());
            }
        }

        return $warnings;
    }

    /** @return list<NotificationChannel> */
    private function channels(): array
    {
        return [new SlackChannel(), new DiscordChannel(), new TeamsChannel(), new EmailChannel()];
    }
}
