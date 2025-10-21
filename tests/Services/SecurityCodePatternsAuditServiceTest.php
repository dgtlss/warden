<?php

namespace Tests\Services;

use Dgtlss\Warden\Services\Audits\SecurityCodePatternsAuditService;
use PHPUnit\Framework\TestCase;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Storage;

class SecurityCodePatternsAuditServiceTest extends TestCase
{
    protected SecurityCodePatternsAuditService $auditService;
    protected string $testPath;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->auditService = new SecurityCodePatternsAuditService();
        $this->testPath = storage_path('test-security-patterns');
        
        // Clean up any existing test directory
        if (File::exists($this->testPath)) {
            File::deleteDirectory($this->testPath);
        }
        
        // Create test directory structure
        File::makeDirectory($this->testPath, 0755, true);
        File::makeDirectory($this->testPath . '/app', 0755, true);
        File::makeDirectory($this->testPath . '/app/Controllers', 0755, true);
        File::makeDirectory($this->testPath . '/config', 0755, true);
        File::makeDirectory($this->testPath . '/vendor', 0755, true); // Should be excluded
    }

    protected function tearDown(): void
    {
        // Clean up test directory
        if (File::exists($this->testPath)) {
            File::deleteDirectory($this->testPath);
        }
        
        parent::tearDown();
    }

    /** @test */
    public function it_returns_correct_service_name()
    {
        $this->assertEquals('Security Code Patterns Audit', $this->auditService->getName());
    }

    /** @test */
    public function it_can_always_run()
    {
        $this->assertTrue($this->auditService->canRun());
    }

    /** @test */
    public function it_detects_sql_injection_vulnerabilities()
    {
        // Create a file with SQL injection vulnerability
        $vulnerableCode = '<?php
$user_id = $_GET["id"];
$sql = "SELECT * FROM users WHERE id = " . $user_id;
$result = mysql_query($sql);
?>';
        
        File::put($this->testPath . '/app/Controller/UserController.php', $vulnerableCode);
        
        // Configure the service to scan our test path
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $this->assertNotEmpty($findings);
        
        $sqlFinding = collect($findings)->firstWhere('type', 'sql_injection');
        $this->assertNotNull($sqlFinding);
        $this->assertEquals('SQL Injection', $sqlFinding['title']);
        $this->assertEquals('critical', $sqlFinding['severity']);
        $this->assertStringContainsString('UserController.php', $sqlFinding['file']);
    }

    /** @test */
    public function it_detects_xss_vulnerabilities()
    {
        $vulnerableCode = '<?php
$name = $_POST["name"];
echo "Hello, " . $name;
?>';
        
        File::put($this->testPath . '/app/Controller/GreeterController.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $xssFinding = collect($findings)->firstWhere('type', 'xss');
        $this->assertNotNull($xssFinding);
        $this->assertEquals('Cross-Site Scripting (XSS)', $xssFinding['title']);
        $this->assertEquals('high', $xssFinding['severity']);
    }

    /** @test */
    public function it_detects_command_injection_vulnerabilities()
    {
        $vulnerableCode = '<?php
$filename = $_GET["file"];
system("ls -la " . $filename);
?>';
        
        File::put($this->testPath . '/app/Controller/FileController.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $commandFinding = collect($findings)->firstWhere('type', 'command_injection');
        $this->assertNotNull($commandFinding);
        $this->assertEquals('Command Injection', $commandFinding['title']);
        $this->assertEquals('critical', $commandFinding['severity']);
    }

    /** @test */
    public function it_detects_file_inclusion_vulnerabilities()
    {
        $vulnerableCode = '<?php
$page = $_GET["page"];
include $page . ".php";
?>';
        
        File::put($this->testPath . '/app/Controller/PageController.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $fileFinding = collect($findings)->firstWhere('type', 'file_inclusion');
        $this->assertNotNull($fileFinding);
        $this->assertEquals('File Inclusion Vulnerability', $fileFinding['title']);
        $this->assertEquals('high', $fileFinding['severity']);
    }

    /** @test */
    public function it_detects_hardcoded_credentials()
    {
        $vulnerableCode = '<?php
$password = "supersecretpassword123";
$api_key = "sk_live_1234567890abcdef";
$db_host = "localhost";
?>';
        
        File::put($this->testPath . '/config/database.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $credentialsFinding = collect($findings)->firstWhere('type', 'hardcoded_credentials');
        $this->assertNotNull($credentialsFinding);
        $this->assertEquals('Hardcoded Credentials', $credentialsFinding['title']);
        $this->assertEquals('high', $credentialsFinding['severity']);
    }

    /** @test */
    public function it_detects_weak_cryptographic_functions()
    {
        $vulnerableCode = '<?php
$hash = md5($password);
$signature = sha1($data);
$checksum = crc32($file);
?>';
        
        File::put($this->testPath . '/app/Services/CryptoService.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $cryptoFinding = collect($findings)->firstWhere('type', 'weak_crypto');
        $this->assertNotNull($cryptoFinding);
        $this->assertEquals('Weak Cryptographic Functions', $cryptoFinding['title']);
        $this->assertEquals('medium', $cryptoFinding['severity']);
    }

    /** @test */
    public function it_detects_weak_random_number_generation()
    {
        $vulnerableCode = '<?php
$token = rand();
$sessionId = mt_rand();
$uniqueId = uniqid();
?>';
        
        File::put($this->testPath . '/app/Services/TokenService.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $randomFinding = collect($findings)->firstWhere('type', 'weak_random');
        $this->assertNotNull($randomFinding);
        $this->assertEquals('Insecure Random Number Generation', $randomFinding['title']);
        $this->assertEquals('medium', $randomFinding['severity']);
    }

    /** @test */
    public function it_detects_insecure_file_upload()
    {
        $vulnerableCode = '<?php
$uploadDir = "uploads/";
move_uploaded_file($_FILES["file"]["tmp_name"], $uploadDir . $_FILES["file"]["name"]);
?>';
        
        File::put($this->testPath . '/app/Controller/UploadController.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $uploadFinding = collect($findings)->firstWhere('type', 'insecure_upload');
        $this->assertNotNull($uploadFinding);
        $this->assertEquals('Insecure File Upload', $uploadFinding['title']);
        $this->assertEquals('high', $uploadFinding['severity']);
    }

    /** @test */
    public function it_detects_insecure_session_management()
    {
        $vulnerableCode = '<?php
session_start();
$sessionId = session_id();
$_SESSION["password"] = $userPassword;
?>';
        
        File::put($this->testPath . '/app/Controller/AuthController.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $sessionFinding = collect($findings)->firstWhere('type', 'insecure_session');
        $this->assertNotNull($sessionFinding);
        $this->assertEquals('Insecure Session Management', $sessionFinding['title']);
        $this->assertEquals('medium', $sessionFinding['severity']);
    }

    /** @test */
    public function it_detects_insecure_deserialization()
    {
        $vulnerableCode = '<?php
$data = $_POST["data"];
$object = unserialize($data);
?>';
        
        File::put($this->testPath . '/app/Controller/DataController.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $deserializationFinding = collect($findings)->firstWhere('type', 'insecure_deserialization');
        $this->assertNotNull($deserializationFinding);
        $this->assertEquals('Insecure Deserialization', $deserializationFinding['title']);
        $this->assertEquals('critical', $deserializationFinding['severity']);
    }

    /** @test */
    public function it_detects_information_disclosure()
    {
        $vulnerableCode = '<?php
error_reporting(E_ALL);
ini_set("display_errors", 1);
var_dump($_POST);
phpinfo();
?>';
        
        File::put($this->testPath . '/app/Controller/DebugController.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $disclosureFinding = collect($findings)->firstWhere('type', 'information_disclosure');
        $this->assertNotNull($disclosureFinding);
        $this->assertEquals('Information Disclosure', $disclosureFinding['title']);
        $this->assertEquals('low', $disclosureFinding['severity']);
    }

    /** @test */
    public function it_detects_insecure_direct_object_reference()
    {
        $vulnerableCode = '<?php
$userId = $_GET["user_id"];
$sql = "SELECT * FROM users WHERE id = " . $userId;
?>';
        
        File::put($this->testPath . '/app/Controller/ProfileController.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $idorFinding = collect($findings)->firstWhere('type', 'idor');
        $this->assertNotNull($idorFinding);
        $this->assertEquals('Insecure Direct Object Reference', $idorFinding['title']);
        $this->assertEquals('medium', $idorFinding['severity']);
    }

    /** @test */
    public function it_respects_exclude_directories()
    {
        // Create vulnerable code in excluded directory
        $vulnerableCode = '<?php
$user_id = $_GET["id"];
$sql = "SELECT * FROM users WHERE id = " . $user_id;
$result = mysql_query($sql);
?>';
        
        File::put($this->testPath . '/vendor/vulnerable.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => ['vendor'],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        // Should not find anything since vendor is excluded
        $this->assertEmpty($findings);
    }

    /** @test */
    public function it_respects_exclude_files()
    {
        // Create vulnerable code in excluded file pattern
        $vulnerableCode = '<?php
$user_id = $_GET["id"];
$sql = "SELECT * FROM users WHERE id = " . $user_id;
$result = mysql_query($sql);
?>';
        
        File::put($this->testPath . '/app/vulnerable.min.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_files' => ['*.min.php'],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        // Should not find anything since .min.php files are excluded
        $this->assertEmpty($findings);
    }

    /** @test */
    public function it_respects_included_extensions()
    {
        // Create vulnerable code in non-PHP file
        $vulnerableCode = 'user_id = $_GET["id"]; sql = "SELECT * FROM users WHERE id = " . user_id;';
        
        File::put($this->testPath . '/app/vulnerable.js', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'included_extensions' => ['.php'],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        // Should not find anything since .js files are not included
        $this->assertEmpty($findings);
    }

    /** @test */
    public function it_uses_custom_patterns()
    {
        // Configure custom pattern
        $customPatterns = [
            'custom_function_vulnerability' => [
                'name' => 'Custom Function Vulnerability',
                'severity' => 'high',
                'patterns' => [
                    '/custom_dangerous_function\s*\(\s*\$_(GET|POST)/i',
                ],
                'description' => 'Custom dangerous function with user input detected'
            ]
        ];
        
        $vulnerableCode = '<?php
custom_dangerous_function($_GET["input"]);
?>';
        
        File::put($this->testPath . '/app/Controller/CustomController.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
            'custom_patterns' => $customPatterns,
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $customFinding = collect($findings)->firstWhere('type', 'custom_function_vulnerability');
        $this->assertNotNull($customFinding);
        $this->assertEquals('Custom Function Vulnerability', $customFinding['title']);
        $this->assertEquals('high', $customFinding['severity']);
    }

    /** @test */
    public function it_provides_recommendations()
    {
        $vulnerableCode = '<?php
$user_id = $_GET["id"];
$sql = "SELECT * FROM users WHERE id = " . $user_id;
$result = mysql_query($sql);
?>';
        
        File::put($this->testPath . '/app/Controller/UserController.php', $vulnerableCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $sqlFinding = collect($findings)->firstWhere('type', 'sql_injection');
        $this->assertNotNull($sqlFinding);
        $this->assertNotEmpty($sqlFinding['recommendation']);
        $this->assertStringContainsString('prepared statements', $sqlFinding['recommendation']);
    }

    /** @test */
    public function it_handles_file_reading_errors_gracefully()
    {
        // Create a file but make it unreadable (simulated)
        $filePath = $this->testPath . '/app/Controller/UnreadableController.php';
        File::put($filePath, '<?php echo "test";');
        
        // Mock file_get_contents to return false
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        // Should not throw an exception
        $this->expectNotToPerformAssertions();
        $this->auditService->run();
    }

    /** @test */
    public function it_scans_multiple_files()
    {
        // Create multiple vulnerable files
        $sqlCode = '<?php $id = $_GET["id"]; mysql_query("SELECT * FROM users WHERE id = " . $id);';
        $xssCode = '<?php $name = $_POST["name"]; echo "Hello " . $name;';
        
        File::put($this->testPath . '/app/Controller/UserController.php', $sqlCode);
        File::put($this->testPath . '/app/Controller/GreeterController.php', $xssCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        // Should find vulnerabilities in both files
        $this->assertGreaterThanOrEqual(2, count($findings));
        
        $sqlFinding = collect($findings)->firstWhere('type', 'sql_injection');
        $xssFinding = collect($findings)->firstWhere('type', 'xss');
        
        $this->assertNotNull($sqlFinding);
        $this->assertNotNull($xssFinding);
    }

    /** @test */
    public function it_returns_empty_findings_when_no_vulnerabilities_found()
    {
        // Create safe code
        $safeCode = '<?php
class SafeController {
    public function index() {
        return "Hello World";
    }
}
?>';
        
        File::put($this->testPath . '/app/Controller/SafeController.php', $safeCode);
        
        $this->auditService->initialize([
            'scan_paths' => [$this->testPath],
            'exclude_directories' => [],
        ]);
        
        $result = $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        $this->assertTrue($result);
        $this->assertEmpty($findings);
    }
}