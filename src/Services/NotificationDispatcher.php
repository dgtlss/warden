<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Contracts\ReportNotificationChannel;
use Dgtlss\Warden\Notifications\Channels\DiscordChannel;
use Dgtlss\Warden\Notifications\Channels\EmailChannel;
use Dgtlss\Warden\Notifications\Channels\SlackChannel;
use Dgtlss\Warden\Notifications\Channels\TeamsChannel;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Throwable;

final class NotificationDispatcher
{
    /** @return list<string> Non-gating delivery warnings. */
    public function send(AuditReport $auditReport, bool $onlyOnFindings = false): array
    {
        $findings = $auditReport->findings();
        $incomplete = $auditReport->errors() !== [];
        $onErrors = config('warden.notifications.on_errors');
        if ($incomplete && $onErrors === false) {
            return [];
        }

        // Only an explicit true opts into error alerts beyond the finding-only filter.
        $errorOptIn = $incomplete && $onErrors === true;
        if (!$errorOptIn && ($onlyOnFindings || config('warden.notifications.only_on_findings', false) === true) && $findings === []) {
            return [];
        }

        $warnings = [];
        foreach ($this->channels() as $reportNotificationChannel) {
            if (!$reportNotificationChannel->isConfigured()) {
                continue;
            }

            try {
                $reportNotificationChannel->sendReport($auditReport);
            } catch (Throwable $throwable) {
                $warnings[] = sprintf('%s notification failed: %s', $reportNotificationChannel->getName(), $throwable->getMessage());
            }
        }

        return $warnings;
    }

    /** @return list<ReportNotificationChannel> */
    private function channels(): array
    {
        return [new SlackChannel(), new DiscordChannel(), new TeamsChannel(), new EmailChannel()];
    }
}
