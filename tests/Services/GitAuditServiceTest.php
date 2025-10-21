<?php

namespace Tests\Services;

use Dgtlss\Warden\Services\Audits\GitAuditService;
use PHPUnit\Framework\TestCase;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Storage;
use Symfony\Component\Process\Process;

class GitAuditServiceTest extends TestCase
{
    protected GitAuditService $gitAuditService;
    protected string $testRepoPath;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->gitAuditService = new GitAuditService();
        $this->testRepoPath = storage_path('test-git-repo');
        
        // Clean up any existing test repo
        if (File::exists($this->testRepoPath)) {
            File::deleteDirectory($this->testRepoPath);
        }
        
        // Create a test git repository
        $this->createTestGitRepository();
    }

    protected function tearDown(): void
    {
        // Clean up test repository
        if (File::exists($this->testRepoPath)) {
            File::deleteDirectory($this->testRepoPath);
        }
        
        parent::tearDown();
    }

    protected function createTestGitRepository(): void
    {
        // Create test directory
        File::makeDirectory($this->testRepoPath, 0755, true);
        
        // Initialize git repository
        $this->runGitCommand(['init'], $this->testRepoPath);
        $this->runGitCommand(['config', 'user.name', 'Test User'], $this->testRepoPath);
        $this->runGitCommand(['config', 'user.email', 'test@example.com'], $this->testRepoPath);
        
        // Create initial commit
        File::put($this->testRepoPath . '/README.md', '# Test Repository');
        $this->runGitCommand(['add', 'README.md'], $this->testRepoPath);
        $this->runGitCommand(['commit', '-m', 'Initial commit'], $this->testRepoPath);
    }

    protected function runGitCommand(array $command, string $workingDir = null): string
    {
        $process = new Process(array_merge(['git'], $command), $workingDir);
        $process->run();
        
        if (!$process->isSuccessful()) {
            throw new \RuntimeException("Git command failed: " . $process->getErrorOutput());
        }
        
        return $process->getOutput();
    }

    /** @test */
    public function it_can_detect_git_repository()
    {
        chdir($this->testRepoPath);
        
        $this->assertTrue($this->gitAuditService->canRun());
    }

    /** @test */
    public function it_fails_when_not_in_git_repository()
    {
        chdir(storage_path());
        
        $this->assertFalse($this->gitAuditService->canRun());
    }

    /** @test */
    public function it_detects_aws_access_keys_in_working_tree()
    {
        chdir($this->testRepoPath);
        
        // Create a file with AWS access key
        File::put($this->testRepoPath . '/config.php', '<?php $key = "AKIAFAKEAWSKEYFORTESTING";');
        
        $this->gitAuditService->run();
        $findings = $this->gitAuditService->getFindings();
        
        $this->assertNotEmpty($findings);
        $this->assertEquals('Git Security Audit', $this->gitAuditService->getName());
        
        $awsFinding = collect($findings)->firstWhere('type', 'aws_access_key');
        $this->assertNotNull($awsFinding);
        $this->assertStringContainsString('AWS Access Key found', $awsFinding['message']);
        $this->assertStringContainsString('config.php', $awsFinding['file']);
    }

    /** @test */
    public function it_detects_github_tokens_in_staged_files()
    {
        chdir($this->testRepoPath);
        
        // Create and stage a file with GitHub token
        File::put($this->testRepoPath . '/.env', 'GITHUB_TOKEN=ghp_FAKE_GITHUB_TOKEN_FOR_TESTING_ONLY');
        $this->runGitCommand(['add', '.env'], $this->testRepoPath);
        
        $this->gitAuditService->run();
        $findings = $this->gitAuditService->getFindings();
        
        $githubFinding = collect($findings)->firstWhere('type', 'github_token');
        $this->assertNotNull($githubFinding);
        $this->assertStringContainsString('GitHub Personal Access Token found', $githubFinding['message']);
        $this->assertStringContainsString('.env', $githubFinding['file']);
    }

    /** @test */
    public function it_detects_secrets_in_commit_history()
    {
        chdir($this->testRepoPath);
        
        // Create a file with secret, commit it, then remove it
        File::put($this->testRepoPath . '/secrets.txt', 'DATABASE_URL=mysql://fakeuser:fakepass@localhost/fakedb');
        $this->runGitCommand(['add', 'secrets.txt'], $this->testRepoPath);
        $this->runGitCommand(['commit', '-m', 'Add secrets'], $this->testRepoPath);
        
        // Remove the file
        File::delete($this->testRepoPath . '/secrets.txt');
        $this->runGitCommand(['add', '-A'], $this->testRepoPath);
        $this->runGitCommand(['commit', '-m', 'Remove secrets'], $this->testRepoPath);
        
        $this->gitAuditService->run();
        $findings = $this->gitAuditService->getFindings();
        
        $dbFinding = collect($findings)->firstWhere('type', 'database_url');
        $this->assertNotNull($dbFinding);
        $this->assertStringContainsString('Database URL found', $dbFinding['message']);
        $this->assertStringContainsString('secrets.txt', $dbFinding['file']);
    }

    /** @test */
    public function it_detects_sensitive_files()
    {
        chdir($this->testRepoPath);
        
        // Create sensitive files
        File::put($this->testRepoPath . '/.env', 'APP_KEY=base64:secret');
        File::put($this->testRepoPath . '/id_rsa', '-----BEGIN RSA PRIVATE KEY-----');
        
        $this->gitAuditService->run();
        $findings = $this->gitAuditService->getFindings();
        
        $envFinding = collect($findings)->firstWhere('type', 'sensitive_file');
        $this->assertNotNull($envFinding);
        $this->assertStringContainsString('.env', $envFinding['message']);
        
        $keyFinding = collect($findings)->firstWhere('type', 'sensitive_file');
        $this->assertNotNull($keyFinding);
        $this->assertStringContainsString('id_rsa', $keyFinding['message']);
    }

    /** @test */
    public function it_detects_large_files()
    {
        chdir($this->testRepoPath);
        
        // Create a large file (over 10MB default threshold)
        $largeContent = str_repeat('A', 11 * 1024 * 1024); // 11MB
        File::put($this->testRepoPath . '/large-file.txt', $largeContent);
        
        $this->gitAuditService->run();
        $findings = $this->gitAuditService->getFindings();
        
        $largeFileFinding = collect($findings)->firstWhere('type', 'large_file');
        $this->assertNotNull($largeFileFinding);
        $this->assertStringContainsString('Large file found', $largeFileFinding['message']);
        $this->assertStringContainsString('large-file.txt', $largeFileFinding['file']);
    }

    /** @test */
    public function it_detects_binary_files()
    {
        chdir($this->testRepoPath);
        
        // Create a binary file
        $binaryContent = "\x00\x01\x02\x03\x04\x05" . str_repeat("\xFF", 2000);
        File::put($this->testRepoPath . '/binary-file.bin', $binaryContent);
        
        $this->gitAuditService->run();
        $findings = $this->gitAuditService->getFindings();
        
        $binaryFileFinding = collect($findings)->firstWhere('type', 'binary_file');
        $this->assertNotNull($binaryFileFinding);
        $this->assertStringContainsString('Binary file found', $binaryFileFinding['message']);
        $this->assertStringContainsString('binary-file.bin', $binaryFileFinding['file']);
    }

    /** @test */
    public function it_respects_exclude_patterns()
    {
        chdir($this->testRepoPath);
        
        // Create a file with secret in vendor directory (should be excluded)
        File::makeDirectory($this->testRepoPath . '/vendor', 0755, true);
        File::put($this->testRepoPath . '/vendor/config.php', '<?php $key = "AKIAFAKEAWSKEYFORTESTING";');
        
        // Configure to exclude vendor directory
        config(['warden.audits.git.exclude_files' => ['vendor/']]);
        
        $this->gitAuditService->run();
        $findings = $this->gitAuditService->getFindings();
        
        // Should not find the secret in vendor directory
        $awsFinding = collect($findings)->firstWhere('type', 'aws_access_key');
        $this->assertNull($awsFinding);
    }

    /** @test */
    public function it_uses_custom_patterns()
    {
        chdir($this->testRepoPath);
        
        // Configure custom pattern
        config(['warden.audits.git.custom_patterns' => [
            [
                'name' => 'custom_api_key',
                'pattern' => '/CUSTOM_API_KEY_[A-Z0-9]{20}/',
                'description' => 'Custom API Key pattern'
            ]
        ]]);
        
        // Create file with custom pattern
        File::put($this->testRepoPath . '/config.json', '{"api_key": "CUSTOM_API_KEY_FAKE_FOR_TESTING_ONLY"}');
        
        $this->gitAuditService->run();
        $findings = $this->gitAuditService->getFindings();
        
        $customFinding = collect($findings)->firstWhere('type', 'custom_api_key');
        $this->assertNotNull($customFinding);
        $this->assertStringContainsString('Custom API Key pattern', $customFinding['message']);
        $this->assertStringContainsString('config.json', $customFinding['file']);
    }

    /** @test */
    public function it_respects_configuration_options()
    {
        // Test that configuration options are respected
        config([
            'warden.audits.git.scan_working_tree' => false,
            'warden.audits.git.scan_staged_files' => false,
            'warden.audits.git.scan_commit_history' => false,
        ]);
        
        chdir($this->testRepoPath);
        
        // Create files with secrets
        File::put($this->testRepoPath . '/config.php', '<?php $key = "AKIAFAKEAWSKEYFORTESTING";');
        $this->runGitCommand(['add', 'config.php'], $this->testRepoPath);
        
        $this->gitAuditService->run();
        $findings = $this->gitAuditService->getFindings();
        
        // Should not find anything since all scanning is disabled
        $this->assertEmpty($findings);
    }

    /** @test */
    public function it_handles_git_command_failures_gracefully()
    {
        chdir($this->testRepoPath);
        
        // Corrupt the git repository to cause command failures
        File::deleteDirectory($this->testRepoPath . '/.git');
        
        $this->gitAuditService->run();
        $findings = $this->gitAuditService->getFindings();
        
        // Should handle the failure gracefully
        $this->assertIsArray($findings);
    }

    /** @test */
    public function it_returns_correct_service_name()
    {
        $this->assertEquals('Git Security Audit', $this->gitAuditService->getName());
    }

    /** @test */
    public function it_detects_various_secret_types()
    {
        chdir($this->testRepoPath);
        
        // Test various secret patterns
        $secrets = [
            'aws_secret.txt' => 'AWS_SECRET_KEY=FAKE_AWS_SECRET_KEY_FOR_TESTING_ONLY',
            'google.txt' => 'GOOGLE_API_KEY=FAKE_GOOGLE_API_KEY_FOR_TESTING_ONLY',
            'slack.txt' => 'xoxb-FAKE_SLACK_TOKEN_FOR_TESTING_ONLY',
            'jwt.txt' => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.FAKE_JWT_TOKEN_FOR_TESTING_ONLY',
        ];
        
        foreach ($secrets as $filename => $content) {
            File::put($this->testRepoPath . '/' . $filename, $content);
        }
        
        $this->gitAuditService->run();
        $findings = $this->gitAuditService->getFindings();
        
        $this->assertNotEmpty($findings);
        
        // Check for specific secret types
        $secretTypes = ['aws_secret_key', 'google_api_key', 'slack_token', 'jwt_token'];
        foreach ($secretTypes as $type) {
            $finding = collect($findings)->firstWhere('type', $type);
            $this->assertNotNull($finding, "Should detect {$type}");
        }
    }

    /** @test */
    public function it_limits_commit_history_scan_depth()
    {
        chdir($this->testRepoPath);
        
        // Create multiple commits with secrets
        for ($i = 1; $i <= 5; $i++) {
            File::put($this->testRepoPath . "/secret{$i}.txt", "SECRET_KEY_{$i}=value{$i}");
            $this->runGitCommand(['add', "secret{$i}.txt"], $this->testRepoPath);
            $this->runGitCommand(['commit', '-m', "Add secret {$i}"], $this->testRepoPath);
        }
        
        // Set history depth to 2
        config(['warden.audits.git.history_depth' => 2]);
        
        $this->gitAuditService->run();
        $findings = $this->gitAuditService->getFindings();
        
        // Should find secrets but limit the history scan
        $this->assertNotEmpty($findings);
        
        // Count findings related to commit history
        $historyFindings = collect($findings)->filter(function ($finding) {
            return isset($finding['source']) && $finding['source'] === 'commit_history';
        });
        
        // Should have limited findings due to depth restriction
        $this->assertLessThanOrEqual(2, $historyFindings->count());
    }
}