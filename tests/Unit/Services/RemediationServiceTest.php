<?php

namespace Dgtlss\Warden\Tests\Unit\Services;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\RemediationService;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\Finding;
use Dgtlss\Warden\ValueObjects\Remediation;

class RemediationServiceTest extends TestCase
{
    private RemediationService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new RemediationService();
    }

    public function testGetSuggestionsReturnsRemediation(): void
    {
        $finding = new Finding(
            source: 'composer',
            package: 'vendor/package',
            title: 'Test vulnerability',
            severity: Severity::HIGH,
        );

        $remediation = $this->service->getSuggestions($finding);

        $this->assertInstanceOf(Remediation::class, $remediation);
        $this->assertNotEmpty($remediation->description);
    }

    public function testGetSuggestionsForComposerFinding(): void
    {
        $finding = new Finding(
            source: 'composer',
            package: 'vendor/package',
            title: 'Security vulnerability',
            severity: Severity::CRITICAL,
            cve: 'CVE-2024-1234',
        );

        $remediation = $this->service->getSuggestions($finding);

        $this->assertStringContainsString('vendor/package', $remediation->description);
        $this->assertTrue($remediation->hasCommands());
        $this->assertContains('composer update vendor/package', $remediation->commands);
        $this->assertTrue($remediation->hasLinks());
        $this->assertEquals('immediate', $remediation->priority);
    }

    public function testGetSuggestionsForNpmFinding(): void
    {
        $finding = new Finding(
            source: 'npm',
            package: 'test-package',
            title: 'Security vulnerability',
            severity: Severity::HIGH,
        );

        $remediation = $this->service->getSuggestions($finding);

        $this->assertStringContainsString('test-package', $remediation->description);
        $this->assertTrue($remediation->hasCommands());
        $this->assertContains('npm update test-package', $remediation->commands);
        $this->assertContains('npm audit fix', $remediation->commands);
        $this->assertEquals('high', $remediation->priority);
    }

    public function testGetSuggestionsForDebugModeFinding(): void
    {
        $finding = new Finding(
            source: 'debug mode',
            package: 'config',
            title: 'Debug mode enabled in production',
            severity: Severity::HIGH,
        );

        $remediation = $this->service->getSuggestions($finding);

        $this->assertStringContainsString('debug', strtolower($remediation->description));
        $this->assertTrue($remediation->hasManualSteps());
        $this->assertFalse($remediation->hasCommands());
    }

    public function testGetSuggestionsForStorageFinding(): void
    {
        $finding = new Finding(
            source: 'storage',
            package: 'storage',
            title: 'Storage not writable',
            severity: Severity::MEDIUM,
        );

        $remediation = $this->service->getSuggestions($finding);

        $this->assertTrue($remediation->hasCommands());
        $this->assertStringContainsString('chmod', $remediation->commands[0]);
        $this->assertEquals('medium', $remediation->priority);
    }

    public function testGetSuggestionsForFilePermissionsFinding(): void
    {
        $finding = new Finding(
            source: 'file permissions',
            package: '.env',
            title: '.env file is world-readable',
            severity: Severity::HIGH,
        );

        $remediation = $this->service->getSuggestions($finding);

        $this->assertTrue($remediation->hasCommands());
        $this->assertContains('chmod 600 .env', $remediation->commands);
    }

    public function testGetSuggestionsForCorsFinding(): void
    {
        $finding = new Finding(
            source: 'cors',
            package: 'cors',
            title: 'Wildcard CORS origin configured',
            severity: Severity::MEDIUM,
        );

        $remediation = $this->service->getSuggestions($finding);

        $this->assertStringContainsString('CORS', $remediation->description);
        $this->assertTrue($remediation->hasManualSteps());
        $this->assertTrue($remediation->hasLinks());
    }

    public function testGetSuggestionsForSslFinding(): void
    {
        $finding = new Finding(
            source: 'ssl',
            package: 'ssl',
            title: 'HTTPS not enforced',
            severity: Severity::HIGH,
        );

        $remediation = $this->service->getSuggestions($finding);

        $this->assertStringContainsString('HTTPS', $remediation->description);
        $this->assertTrue($remediation->hasManualSteps());
    }

    public function testGetSuggestionsForSecurityHeadersFinding(): void
    {
        $finding = new Finding(
            source: 'security headers',
            package: 'headers',
            title: 'Missing X-Frame-Options header',
            severity: Severity::MEDIUM,
        );

        $remediation = $this->service->getSuggestions($finding);

        $this->assertStringContainsString('security headers', strtolower($remediation->description));
        $this->assertTrue($remediation->hasManualSteps());
        $this->assertTrue($remediation->hasLinks());
    }

    public function testGetSuggestionsForDatabaseSecurityFinding(): void
    {
        $finding = new Finding(
            source: 'database security',
            package: 'database',
            title: 'Weak database password',
            severity: Severity::HIGH,
        );

        $remediation = $this->service->getSuggestions($finding);

        $this->assertTrue($remediation->hasManualSteps());
    }

    public function testGetSuggestionsForEnvFinding(): void
    {
        $finding = new Finding(
            source: 'env',
            package: 'env',
            title: 'Missing APP_KEY',
            severity: Severity::HIGH,
        );

        $remediation = $this->service->getSuggestions($finding);

        $this->assertTrue($remediation->hasCommands() || $remediation->hasManualSteps());
        $this->assertTrue($remediation->hasLinks());
    }

    public function testGetSuggestionsForConfigFinding(): void
    {
        $finding = new Finding(
            source: 'config',
            package: 'config',
            title: 'Insecure configuration',
            severity: Severity::MEDIUM,
        );

        $remediation = $this->service->getSuggestions($finding);

        $this->assertTrue($remediation->hasCommands());
        $this->assertTrue($remediation->hasManualSteps());
    }

    public function testGetSuggestionsForUnknownSource(): void
    {
        $finding = new Finding(
            source: 'unknown_source',
            package: 'package',
            title: 'Some issue',
            severity: Severity::LOW,
            cve: 'CVE-2024-5678',
        );

        $remediation = $this->service->getSuggestions($finding);

        $this->assertInstanceOf(Remediation::class, $remediation);
        $this->assertTrue($remediation->hasManualSteps());
        $this->assertTrue($remediation->hasLinks());
        $this->assertEquals('low', $remediation->priority);
    }

    public function testPriorityDeterminationBySeverity(): void
    {
        $critical = new Finding(source: 'test', package: 'p', title: 't', severity: Severity::CRITICAL);
        $high = new Finding(source: 'test', package: 'p', title: 't', severity: Severity::HIGH);
        $medium = new Finding(source: 'test', package: 'p', title: 't', severity: Severity::MEDIUM);
        $low = new Finding(source: 'test', package: 'p', title: 't', severity: Severity::LOW);

        $this->assertEquals('immediate', $this->service->getSuggestions($critical)->priority);
        $this->assertEquals('high', $this->service->getSuggestions($high)->priority);
        $this->assertEquals('medium', $this->service->getSuggestions($medium)->priority);
        $this->assertEquals('low', $this->service->getSuggestions($low)->priority);
    }

    public function testGetSuggestionsForAllReturnsArrayOfRemediations(): void
    {
        $findings = [
            new Finding(source: 'composer', package: 'vendor/a', title: 'Vuln A', severity: Severity::HIGH),
            new Finding(source: 'npm', package: 'package-b', title: 'Vuln B', severity: Severity::MEDIUM),
        ];

        $remediations = $this->service->getSuggestionsForAll($findings);

        $this->assertCount(2, $remediations);
        $this->assertInstanceOf(Remediation::class, $remediations[0]);
        $this->assertInstanceOf(Remediation::class, $remediations[1]);
    }

    public function testEnrichFindingsAddsRemediation(): void
    {
        $findings = [
            new Finding(source: 'composer', package: 'vendor/a', title: 'Vuln A', severity: Severity::HIGH),
            new Finding(source: 'npm', package: 'package-b', title: 'Vuln B', severity: Severity::MEDIUM),
        ];

        $enriched = $this->service->enrichFindings($findings);

        $this->assertCount(2, $enriched);
        $this->assertTrue($enriched[0]->hasRemediation());
        $this->assertTrue($enriched[1]->hasRemediation());
        $this->assertInstanceOf(Remediation::class, $enriched[0]->remediation);
        $this->assertInstanceOf(Remediation::class, $enriched[1]->remediation);
    }

    public function testEnrichFindingsPreservesOriginalData(): void
    {
        $finding = new Finding(
            source: 'composer',
            package: 'vendor/package',
            title: 'Test vulnerability',
            severity: Severity::HIGH,
            cve: 'CVE-2024-1234',
            affectedVersions: '<1.0.0',
        );

        $enriched = $this->service->enrichFindings([$finding]);

        $this->assertEquals('composer', $enriched[0]->source);
        $this->assertEquals('vendor/package', $enriched[0]->package);
        $this->assertEquals('Test vulnerability', $enriched[0]->title);
        $this->assertSame(Severity::HIGH, $enriched[0]->severity);
        $this->assertEquals('CVE-2024-1234', $enriched[0]->cve);
        $this->assertEquals('<1.0.0', $enriched[0]->affectedVersions);
    }

    public function testCveLinksAreIncludedWhenPresent(): void
    {
        $findingWithCve = new Finding(
            source: 'composer',
            package: 'vendor/package',
            title: 'Vulnerability',
            severity: Severity::HIGH,
            cve: 'CVE-2024-1234',
        );

        $remediation = $this->service->getSuggestions($findingWithCve);

        $this->assertTrue($remediation->hasLinks());
        $hasNvdLink = false;
        foreach ($remediation->links as $link) {
            if (str_contains($link, 'nvd.nist.gov') && str_contains($link, 'CVE-2024-1234')) {
                $hasNvdLink = true;
                break;
            }
        }
        $this->assertTrue($hasNvdLink, 'NVD link should be included when CVE is present');
    }

    public function testSourceMatchingIsCaseInsensitive(): void
    {
        $finding1 = new Finding(source: 'COMPOSER', package: 'p', title: 't', severity: Severity::HIGH);
        $finding2 = new Finding(source: 'Composer Audit', package: 'p', title: 't', severity: Severity::HIGH);
        $finding3 = new Finding(source: 'NPM AUDIT', package: 'p', title: 't', severity: Severity::HIGH);

        $rem1 = $this->service->getSuggestions($finding1);
        $rem2 = $this->service->getSuggestions($finding2);
        $rem3 = $this->service->getSuggestions($finding3);

        $this->assertTrue($rem1->hasCommands());
        $this->assertTrue($rem2->hasCommands());
        $this->assertTrue($rem3->hasCommands());
    }
}
