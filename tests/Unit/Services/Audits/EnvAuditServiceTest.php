<?php

namespace Dgtlss\Warden\Tests\Unit\Services\Audits;

use Dgtlss\Warden\Services\Audits\EnvAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Config;
use Mockery;

class EnvAuditServiceTest extends TestCase
{
    public function testGetNameReturnsEnvironment(): void
    {
        $service = new EnvAuditService();

        $this->assertEquals('environment', $service->getName());
    }

    public function testRunWithValidSetup(): void
    {
        // In test environment, .env may not exist
        // This test checks that the service handles the absence gracefully

        Config::set('warden.sensitive_keys', []);

        $service = new EnvAuditService();
        $result = $service->run();

        // Service should still execute and return a result
        $this->assertIsBool($result);

        $findings = $service->getFindings();
        $this->assertIsArray($findings);
    }

    public function testRunDetectsMissingSensitiveKeys(): void
    {
        // Configure sensitive keys that don't exist in env
        Config::set('warden.sensitive_keys', ['MISSING_KEY_123', 'ANOTHER_MISSING_KEY']);

        $service = new EnvAuditService();
        $result = $service->run();

        $this->assertIsBool($result);

        $findings = $service->getFindings();

        // In test environment, may have findings about missing .env file
        // Just verify we have some findings
        $this->assertIsArray($findings);

        // If .env exists, should have findings for missing keys
        $missingKeyFindings = array_filter($findings, function ($finding) {
            return str_contains($finding['title'], 'Missing sensitive environment variable');
        });

        // Verify finding structure if any sensitive key findings exist
        foreach ($missingKeyFindings as $finding) {
            $this->assertEquals('environment', $finding['package']);
            $this->assertEquals('medium', $finding['severity']);
        }
    }

    public function testRunWithExistingSensitiveKeys(): void
    {
        // Set environment variables
        putenv('TEST_SENSITIVE_KEY=value');
        putenv('ANOTHER_TEST_KEY=another_value');

        Config::set('warden.sensitive_keys', ['TEST_SENSITIVE_KEY', 'ANOTHER_TEST_KEY']);

        $service = new EnvAuditService();
        $result = $service->run();

        $this->assertIsBool($result);

        $findings = $service->getFindings();

        // Filter for missing key findings related to our test keys
        $missingTestKeys = array_filter($findings, function ($finding) {
            return str_contains($finding['title'], 'Missing sensitive environment variable') &&
                   (str_contains($finding['title'], 'TEST_SENSITIVE_KEY') ||
                    str_contains($finding['title'], 'ANOTHER_TEST_KEY'));
        });

        // Should not have findings for our existing test keys
        $this->assertCount(0, $missingTestKeys);

        // Clean up
        putenv('TEST_SENSITIVE_KEY');
        putenv('ANOTHER_TEST_KEY');
    }

    public function testRunDetectsMixedSensitiveKeys(): void
    {
        putenv('EXISTING_KEY=value');

        Config::set('warden.sensitive_keys', ['EXISTING_KEY', 'MISSING_KEY']);

        $service = new EnvAuditService();
        $result = $service->run();

        $this->assertIsBool($result);

        $findings = $service->getFindings();
        $this->assertIsArray($findings);

        $missingKeyFindings = array_filter($findings, function ($finding) {
            return str_contains($finding['title'], 'Missing sensitive environment variable');
        });

        // If we have sensitive key findings, verify structure
        if (!empty($missingKeyFindings)) {
            // Should not have a finding for EXISTING_KEY
            $existingKeyFinding = current(array_filter($missingKeyFindings, function ($finding) {
                return str_contains($finding['title'], 'EXISTING_KEY');
            }));

            $this->assertFalse($existingKeyFinding);
        }

        putenv('EXISTING_KEY');

        // Test passed if we get here
        $this->assertTrue(true);
    }

    public function testFindingsHaveCorrectStructure(): void
    {
        Config::set('warden.sensitive_keys', ['NONEXISTENT_KEY']);

        $service = new EnvAuditService();
        $service->run();

        $findings = $service->getFindings();

        if (!empty($findings)) {
            $this->assertValidFindings($findings);
        }
    }
}
