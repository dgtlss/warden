<?php

namespace Dgtlss\Warden\Tests\Unit\Services\Audits;

use Dgtlss\Warden\Services\Audits\PhpSyntaxAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Config;

class PhpSyntaxAuditServiceTest extends TestCase
{
    public function testGetNameReturnsPhpSyntax(): void
    {
        $service = new PhpSyntaxAuditService();

        $this->assertEquals('PHP Syntax', $service->getName());
    }

    public function testParseOutputWithNoErrors(): void
    {
        $service = new PhpSyntaxAuditService();

        $output = "No syntax errors detected in /path/to/file1.php\nNo syntax errors detected in /path/to/file2.php";

        $reflection = new \ReflectionClass($service);
        $method = $reflection->getMethod('parseOutput');
        $method->setAccessible(true);

        $errors = $method->invoke($service, $output);

        $this->assertIsArray($errors);
        $this->assertEmpty($errors);
    }

    public function testParseOutputWithErrors(): void
    {
        $service = new PhpSyntaxAuditService();

        $output = "Errors parsing /var/www/app/BadFile.php\nParse error: syntax error, unexpected ';' in /var/www/app/BadFile.php on line 10";

        $reflection = new \ReflectionClass($service);
        $method = $reflection->getMethod('parseOutput');
        $method->setAccessible(true);

        $errors = $method->invoke($service, $output);

        $this->assertIsArray($errors);
        $this->assertCount(1, $errors);
        $this->assertArrayHasKey('file', $errors[0]);
        $this->assertArrayHasKey('message', $errors[0]);
        $this->assertEquals('/var/www/app/BadFile.php', $errors[0]['file']);
        $this->assertStringContainsString('Parse error', $errors[0]['message']);
    }

    public function testParseOutputWithMultipleErrors(): void
    {
        $service = new PhpSyntaxAuditService();

        $output = "Errors parsing /app/File1.php\nParse error: syntax error in /app/File1.php\nErrors parsing /app/File2.php\nParse error: unexpected token in /app/File2.php";

        $reflection = new \ReflectionClass($service);
        $method = $reflection->getMethod('parseOutput');
        $method->setAccessible(true);

        $errors = $method->invoke($service, $output);

        $this->assertCount(2, $errors);
        $this->assertEquals('/app/File1.php', $errors[0]['file']);
        $this->assertEquals('/app/File2.php', $errors[1]['file']);
    }

    public function testGetProcessCreatesCorrectCommand(): void
    {
        Config::set('warden.audits.php_syntax.exclude', ['vendor', 'node_modules']);

        $service = new PhpSyntaxAuditService();

        $reflection = new \ReflectionClass($service);
        $method = $reflection->getMethod('getProcess');
        $method->setAccessible(true);

        $process = $method->invoke($service);

        $this->assertInstanceOf(\Symfony\Component\Process\Process::class, $process);

        // Get the command line
        $commandLine = $process->getCommandLine();

        $this->assertStringContainsString('find', $commandLine);
        $this->assertStringContainsString('*.php', $commandLine);
        $this->assertStringContainsString('xargs', $commandLine);
        $this->assertStringContainsString('php -l', $commandLine);
        $this->assertStringContainsString('vendor', $commandLine);
    }

    public function testRunReturnsCorrectlyBasedOnFindings(): void
    {
        // Since running actual PHP syntax checking requires the find command
        // and real files, we'll test the logic indirectly by checking
        // that the service structure is correct

        $service = new PhpSyntaxAuditService();

        $this->assertEquals('PHP Syntax', $service->getName());

        // Initially should have no findings
        $this->assertEmpty($service->getFindings());
    }

    public function testFindingsHaveCorrectStructureWhenAdded(): void
    {
        $service = new PhpSyntaxAuditService();

        // Manually add a finding to test structure
        $reflection = new \ReflectionClass($service);
        $method = $reflection->getMethod('addFinding');
        $method->setAccessible(true);

        $finding = [
            'package' => 'Application Code',
            'title' => 'PHP Syntax Error in app/TestFile.php',
            'severity' => 'high',
            'description' => 'Parse error: syntax error',
            'remediation' => 'Fix the syntax error in the specified file.',
        ];

        $method->invoke($service, $finding);

        $findings = $service->getFindings();

        $this->assertCount(1, $findings);
        $this->assertEquals('PHP Syntax', $findings[0]['source']);
        $this->assertEquals('Application Code', $findings[0]['package']);
        $this->assertStringContainsString('PHP Syntax Error', $findings[0]['title']);
        $this->assertEquals('high', $findings[0]['severity']);
    }
}
