<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Reporters;

use Dgtlss\Warden\Contracts\ReportFormatter;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Dgtlss\Warden\ValueObjects\Finding;
use JsonException;

final class SarifReporter implements ReportFormatter
{
    /** @throws JsonException */
    public function format(AuditReport $auditReport): string
    {
        $findings = $auditReport->findings();
        $rules = [];
        foreach ($findings as $finding) {
            $rules[$finding->id] = [
                'id' => $finding->id,
                'shortDescription' => ['text' => $finding->title],
                'fullDescription' => ['text' => $finding->description],
                'help' => ['text' => $finding->remediation ?? $finding->description],
                'properties' => [
                    'security-severity' => (string) ($finding->severity->weight() * 2.5),
                    'blocking' => $finding->blocking,
                ],
            ];
        }

        $payload = [
            'version' => '2.1.0',
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'runs' => [[
                'tool' => ['driver' => ['name' => 'Warden', 'informationUri' => 'https://github.com/dgtlss/warden', 'rules' => array_values($rules)]],
                'results' => array_map(fn (Finding $finding): array => $this->result($finding), $findings),
                'invocations' => [[
                    'executionSuccessful' => $auditReport->errors() === [],
                    'toolExecutionNotifications' => array_map(static fn ($error): array => [
                        'level' => 'error',
                        'message' => ['text' => sprintf('%s: %s', $error->code, $error->message)],
                    ], $auditReport->errors()),
                ]],
            ]],
        ];

        return json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL;
    }

    /** @return array<string, mixed> */
    private function result(Finding $finding): array
    {
        $result = [
            'ruleId' => $finding->id,
            'level' => $finding->blocking ? match ($finding->severity->value) {
                'critical', 'high' => 'error',
                'medium' => 'warning',
                default => 'note',
            } : 'note',
            'message' => ['text' => $finding->title . ' — ' . $finding->description],
            'partialFingerprints' => ['wardenFingerprint/v1' => $finding->fingerprint()],
            'properties' => ['blocking' => $finding->blocking],
        ];

        if ($finding->path !== null) {
            $result['locations'] = [[
                'physicalLocation' => [
                    'artifactLocation' => ['uri' => $finding->path],
                ],
            ]];
            if ($finding->line !== null) {
                $result['locations'][0]['physicalLocation']['region'] = ['startLine' => $finding->line];
            }
        }

        return $result;
    }
}
