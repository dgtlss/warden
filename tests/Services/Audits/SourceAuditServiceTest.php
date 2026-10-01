<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services\Audits;

use Dgtlss\Warden\Services\Audits\SourceAuditService;
use Dgtlss\Warden\Services\RulePolicy;
use Dgtlss\Warden\Services\Source\PhpSourceAnalyzer;
use Dgtlss\Warden\Reporters\ConsoleReporter;
use Dgtlss\Warden\Reporters\GitHubReporter;
use Dgtlss\Warden\Reporters\GitLabReporter;
use Dgtlss\Warden\Reporters\JsonReporter;
use Dgtlss\Warden\Reporters\JunitReporter;
use Dgtlss\Warden\Reporters\SarifReporter;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditReport;
use PHPUnit\Framework\Attributes\DataProvider;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionProperty;
use SplFileInfo;
use Symfony\Component\Finder\SplFileInfo as FinderFileInfo;

final class SourceAuditServiceTest extends TestCase
{
    private string $originalBasePath;

    private string $temporaryBasePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->originalBasePath = $this->app->basePath();
        $this->temporaryBasePath = sys_get_temp_dir() . '/warden-source-' . bin2hex(random_bytes(8));
        mkdir($this->temporaryBasePath . '/app', 0777, true);
        mkdir($this->temporaryBasePath . '/resources/views', 0777, true);
        $this->app->setBasePath($this->temporaryBasePath);
    }

    protected function tearDown(): void
    {
        $this->app->setBasePath($this->originalBasePath);
        if (is_dir($this->temporaryBasePath)) {
            $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->temporaryBasePath, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($iterator as $item) {
                if ($item instanceof SplFileInfo) {
                    $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
                }
            }

            rmdir($this->temporaryBasePath);
        }

        parent::tearDown();
    }

    public function testBlockingTaintAndConstantRulesAreDetected(): void
    {
        $this->write('app/DangerousController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class DangerousController
{
    public function run($request)
    {
        $url = $request->input('url');
        $path = $request->input('path');
        $command = $request->input('command');
        $id = $request->input('id');
        Http::get(
            $url,
        );
        Storage::get($path);
        system($command);
        DB::select("select * from users where id = $id");
        unserialize($request->input('payload'));
        redirect($request->input('next'));
        echo $request->input('name');
        Http::withoutVerifying();
        openssl_encrypt('data', 'des-ecb', 'key');
        app()->withoutMiddleware([PreventRequestForgery::class]);
    }
}
PHP);

        $auditResult = $this->service()->run(new AuditContext());
        $ids = array_column(array_map(static fn ($finding): array => ['id' => $finding->id], $auditResult->findings), 'id');

        self::assertContains('source.php.ssrf-tainted-url', $ids);
        self::assertContains('source.php.path-traversal', $ids);
        self::assertContains('source.php.command-tainted-input', $ids);
        self::assertContains('source.php.sql-dynamic-raw', $ids);
        self::assertContains('source.php.unsafe-deserialization', $ids);
        self::assertContains('source.php.open-redirect', $ids);
        self::assertContains('source.php.xss-tainted-output', $ids);
        self::assertContains('source.php.tls-verification-disabled', $ids);
        self::assertContains('source.php.weak-cipher', $ids);
        self::assertContains('source.laravel.csrf-disabled', $ids);
        self::assertSame([], $auditResult->errors);
    }

    public function testAdvisoriesAreVisibleAndSanitizersAvoidBlockingFindings(): void
    {
        $this->write('app/Reviewed.php', <<<'PHP'
<?php
class Reviewed
{
    protected $guarded = [];
    public function run($request)
    {
        echo e($request->input('name'));
        system(escapeshellarg($request->input('command')));
        $resetToken = uniqid();
        Log::info('token', [$request->input('token')]);
        dd('local only');
    }
}
PHP);
        $this->write('resources/views/form.blade.php', '<form method="POST">{!! $body !!}</form>');

        $auditResult = $this->service()->run(new AuditContext());
        $byId = [];
        foreach ($auditResult->findings as $finding) {
            $byId[$finding->id] = $finding;
        }

        self::assertArrayHasKey('source.laravel.mass-assignment-disabled', $byId);
        self::assertArrayHasKey('source.php.insecure-rng-context', $byId);
        self::assertArrayHasKey('source.php.sensitive-log', $byId);
        self::assertArrayHasKey('source.php.debug-call', $byId);
        self::assertArrayHasKey('source.blade.unescaped-output', $byId);
        self::assertArrayHasKey('source.blade.form-missing-csrf', $byId);
        self::assertFalse($byId['source.blade.unescaped-output']->blocking);
        self::assertArrayNotHasKey('source.php.xss-tainted-output', $byId);
        self::assertArrayNotHasKey('source.php.command-tainted-input', $byId);
    }

    #[DataProvider('secretLiteralContextProvider')]
    public function testSecretLiteralsAreClassifiedByContext(string $path, string $source, bool $reported): void
    {
        $this->write($path, $source);

        $auditResult = $this->service()->run(new AuditContext());

        self::assertSame([], $auditResult->errors);
        self::assertSame($reported, in_array('source.secrets.suspicious-literal', array_column($auditResult->findings, 'id'), true));
    }

    /** @return iterable<string, array{string, string, bool}> */
    public static function secretLiteralContextProvider(): iterable
    {
        foreach (['P@ssw0rd%2026', 'A9{xK!7w}Q2', 'A9|xK!7wQ2', 'correct horse battery staple', 'Qwertyuiopasdfgh', 'password', 'PASSWORD', 'xKjhGfds-aQwErTyZ', 'aGVsbG9Xb3JsZFRoaXNJc0FTZWNyZXQ='] as $password) {
            yield 'credential: ' . $password => ['app/Credentials.php', '<?php $password = ' . var_export($password, true) . ';', true];
        }

        yield 'ambiguous rule-shaped credential' => ['app/Credentials.php', "<?php return ['password' => 'required|min:3'];", true];
        yield 'ambiguous field-shaped credential' => ['app/Credentials.php', "<?php return ['api_key' => 'api_access_token'];", true];
        yield 'request validation' => ['app/Controller.php', "<?php \$request->validate(['access_token' => 'required|min:3']);", false];
        yield 'validation field reference' => ['app/Controller.php', "<?php \$request->validate(['password' => 'required|same:password']);", false];
        yield 'named validation arguments' => ['app/Controller.php', "<?php \$request->validate(rules: ['password' => 'required_if:status,active']);", false];
        yield 'first-class validation callback' => ['app/Controller.php', "<?php \$validate = \$request->validate(...); \$password = 'P@ssw0rd%2026';", true];
        yield 'validation error bag' => ['app/Controller.php', "<?php \$request->validateWithBag('login', ['password' => 'required|same:password']);", false];
        yield 'facade validation' => ['app/Controller.php', "<?php use Illuminate\\Support\\Facades\\Validator; Validator::make([], ['password' => 'regex:/^[A-Z]+$/']);", false];
        yield 'aliased facade validation' => ['app/Controller.php', "<?php use Illuminate\\Support\\Facades\\Validator as V; V::make([], ['access_token' => 'required|min:3']);", false];
        yield 'credentials in validation data' => ['app/Controller.php', "<?php Validator::make(['password' => 'P@ssw0rd%2026'], ['password' => 'required|min:3']);", true];
        yield 'helper validation' => ['app/Controller.php', "<?php validator([], ['password' => ['required', 'same:password']]);", false];
        yield 'form request rules' => ['app/LoginRequest.php', "<?php use Illuminate\\Foundation\\Http\\FormRequest; class LoginRequest extends FormRequest { public function rules(): array { return ['password' => 'required|same:password']; } }", false];
        yield 'conditional form request rules' => ['app/LoginRequest.php', "<?php use Illuminate\\Foundation\\Http\\FormRequest; class LoginRequest extends FormRequest { public function rules(): array { if (true) { return ['password' => 'required|same:password']; } return []; } }", false];
        yield 'credentials in nested closure' => ['app/LoginRequest.php', "<?php use Illuminate\\Foundation\\Http\\FormRequest; class LoginRequest extends FormRequest { public function rules(): array { \$credentials = function () { return ['password' => 'P@ssw0rd%2026']; }; return ['password' => 'required|same:password']; } }", true];
        yield 'unrelated rules method' => ['app/Credentials.php', "<?php class Credentials { public function rules(): array { return ['password' => 'P@ssw0rd%2026']; } }", true];
        yield 'translation sentence' => ['lang/en/auth.php', "<?php return ['password' => 'The password is incorrect'];", false];
        yield 'nested translation label' => ['resources/lang/en/auth.php', "<?php return ['fields' => ['password' => 'Password']];", false];
        yield 'credential assignment in translation file' => ['lang/en/auth.php', "<?php \$password = 'P@ssw0rd%2026'; return ['password' => 'Password'];", true];
        yield 'wildcard field name' => ['app/Fields.php', "<?php return ['%_access_token' => 'api_access_token'];", false];
        yield 'prefixed secret variable' => ['app/Credentials.php', "<?php \$database_password = 'P@ssw0rd%2026';", true];
        yield 'camel case secret variable' => ['app/Credentials.php', "<?php \$clientSecret = 'Qwertyuiopasdfgh';", true];
        yield 'javascript credential' => ['resources/js/credentials.js', "const password = 'correct horse battery staple';", true];
    }

    public function testValidationDoesNotHideOtherSecretsOnTheSameLine(): void
    {
        $secret = '43b38433ec597605e63c7e9d67c52539';
        $this->write('app/Controller.php', sprintf("<?php \$request->validate(['password' => 'required|min:3']); \$api_key = '%s'; \$secret = 'xKjhGfds-aQwErTyZ';", $secret));

        $auditResult = $this->service()->run(new AuditContext());

        self::assertSame([], $auditResult->errors);
        self::assertCount(2, $auditResult->findings);
        self::assertSame([1, 1], array_column($auditResult->findings, 'line'));
        self::assertNotSame($auditResult->findings[0]->fingerprint(), $auditResult->findings[1]->fingerprint());
        self::assertStringNotContainsString($secret, json_encode($auditResult, JSON_THROW_ON_ERROR));
    }

    public function testProviderCredentialsRemainVisibleInNonSecretContexts(): void
    {
        $secret = 'ghp_' . str_repeat('A', 36);
        $this->write('lang/en/auth.php', sprintf("<?php return ['password' => '%s'];", $secret));
        $this->write('app/Controller.php', sprintf("<?php \$request->validate(['access_token' => '%s']);", $secret));

        $auditResult = $this->service()->run(new AuditContext());

        self::assertSame([], $auditResult->errors);
        self::assertCount(2, $auditResult->findings);
        self::assertSame(['source.secrets.provider-credential', 'source.secrets.provider-credential'], array_column($auditResult->findings, 'id'));
        self::assertStringNotContainsString($secret, json_encode($auditResult, JSON_THROW_ON_ERROR));
    }

    public function testSuspiciousLiteralFingerprintsAndRuleOverridesArePreserved(): void
    {
        $this->write('app/Credentials.php', "<?php \$password = 'correct horse battery staple';");
        $finding = $this->finding('source.secrets.suspicious-literal');
        $this->write('app/Credentials.php', "<?php\n\n\$password = 'correct horse battery staple';");
        $second = $this->finding('source.secrets.suspicious-literal');

        self::assertFalse($finding->blocking);
        self::assertSame($finding->fingerprint(), $second->fingerprint());
        self::assertNotSame($finding->line, $second->line);

        config(['warden.rule_overrides' => ['source.secrets.suspicious-literal' => 'enforced']]);
        $enforced = (new RulePolicy())->apply([$this->service()->run(new AuditContext())])[0];
        self::assertTrue($enforced->findings[0]->blocking);

        config(['warden.rule_overrides' => ['source.secrets.suspicious-literal' => 'off']]);
        self::assertSame([], $this->service()->run(new AuditContext())->findings);
    }

    public function testSecretsAreRedactedAndFingerprintsSurviveLineMovement(): void
    {
        $secret = 'ghp_' . str_repeat('A', 36);
        $source = "<?php\nreturn ['token' => '" . $secret . "'];\n";
        $this->write('app/Secret.php', $source);

        $finding = $this->finding('source.secrets.provider-credential');
        self::assertStringNotContainsString($secret, json_encode($finding, JSON_THROW_ON_ERROR));

        $auditResult = $this->service()->run(new AuditContext());
        $auditReport = new AuditReport(new AuditContext(), [$auditResult]);
        foreach ([new ConsoleReporter(), new JsonReporter(), new GitHubReporter(), new GitLabReporter(), new SarifReporter(), new JunitReporter()] as $reporter) {
            self::assertStringNotContainsString($secret, $reporter->format($auditReport));
        }

        $this->write('app/Secret.php', "<?php\n\n\nreturn ['token' => '" . $secret . "'];\n");
        $second = $this->finding('source.secrets.provider-credential');

        self::assertSame($finding->fingerprint(), $second->fingerprint());
        self::assertNotSame($finding->line, $second->line);
    }

    public function testParseErrorsMakeTheAuditIncomplete(): void
    {
        $this->write('app/Broken.php', '<?php function broken( {');

        $auditResult = $this->service()->run(new AuditContext());

        self::assertSame('parse_error', $auditResult->errors[0]->code);
        self::assertFalse($auditResult->succeeded());
    }

    public function testPhp85SyntaxIsAccepted(): void
    {
        $this->write('app/Pipeline.php', '<?php $result = "warden" |> strtoupper(...);');

        $auditResult = $this->service()->run(new AuditContext());

        self::assertSame([], $auditResult->errors);
    }

    public function testOversizedFilesAndTimeoutsAreIncompleteWhileExclusionsAreHonoured(): void
    {
        config([
            'warden.audits.source.max_file_size_kb' => 1,
            'warden.audits.source.exclude' => ['Excluded.php'],
        ]);
        $this->write('app/Large.php', '<?php /*' . str_repeat('x', 2048) . '*/');
        $this->write('app/Excluded.php', '<?php dd("excluded");');

        $auditResult = $this->service()->run(new AuditContext());
        self::assertContains('file_too_large', array_map(static fn ($error): string => $error->code, $auditResult->errors));
        self::assertNotContains('source.php.debug-call', array_map(static fn ($finding): string => $finding->id, $auditResult->findings));

        config(['warden.audits.source.max_file_size_kb' => 1024]);
        $service = new class(
            $this->app->make(\Dgtlss\Warden\Services\Source\SourceFileDiscovery::class),
            $this->app->make(\Dgtlss\Warden\Services\Source\PhpSourceAnalyzer::class),
            $this->app->make(\Dgtlss\Warden\Services\Source\TextSourceAnalyzer::class),
        ) extends SourceAuditService {
            protected function timedOut(float $startedAt, int $timeout): bool { return true; }
        };
        $timedOut = $service->run(new AuditContext());
        self::assertSame('timeout', $timedOut->errors[0]->code);
    }

    public function testTimeoutAfterBladeAnalysisSkipsPhpAnalysis(): void
    {
        $this->write('resources/views/output.blade.php', '{!! $body !!}');
        $this->write('app/Broken.php', '<?php function broken( {');
        $service = new class(
            $this->app->make(\Dgtlss\Warden\Services\Source\SourceFileDiscovery::class),
            $this->app->make(\Dgtlss\Warden\Services\Source\PhpSourceAnalyzer::class),
            $this->app->make(\Dgtlss\Warden\Services\Source\TextSourceAnalyzer::class),
        ) extends SourceAuditService {
            private int $checks = 0;

            protected function timedOut(float $startedAt, int $timeout): bool
            {
                $this->checks++;

                return $this->checks >= 3;
            }
        };

        $auditResult = $service->run(new AuditContext());

        self::assertSame('timeout', $auditResult->errors[0]->code);
        self::assertContains('source.blade.unescaped-output', array_map(static fn ($finding): string => $finding->id, $auditResult->findings));
        self::assertNotContains('parse_error', array_map(static fn ($error): string => $error->code, $auditResult->errors));
    }

    public function testRuleOverridesCanPromoteDisableAndRejectRules(): void
    {
        config(['warden.rule_overrides' => [
            'source.blade.unescaped-output' => 'enforced',
            'source.php.debug-call' => 'off',
        ]]);
        $rulePolicy = new RulePolicy();
        $result = $rulePolicy->apply([$this->resultWithAdvisories()])[0];
        $byId = [];
        foreach ($result->findings as $finding) {
            $byId[$finding->id] = $finding;
        }

        self::assertTrue($byId['source.blade.unescaped-output']->blocking);
        self::assertArrayNotHasKey('source.php.debug-call', $byId);
        self::assertSame([], $rulePolicy->errors());

        config(['warden.rule_overrides' => ['not-a-rule' => 'off']]);
        self::assertSame('unknown_rule', (new RulePolicy())->errors()[0]->code);
    }

    public function testSourcePathsCannotEscapeTheApplicationRoot(): void
    {
        config(['warden.audits.source.php_paths' => ['../outside']]);

        $auditResult = $this->service()->run(new AuditContext());

        self::assertSame('invalid_configuration', $auditResult->errors[0]->code);
    }

    public function testPhpParserInstanceIsReusedAcrossFiles(): void
    {
        $this->write('app/First.php', '<?php return 1;');
        $this->write('app/Second.php', '<?php return 2;');
        $phpSourceAnalyzer = $this->app->make(PhpSourceAnalyzer::class);
        $reflectionProperty = new ReflectionProperty(PhpSourceAnalyzer::class, 'parser');
        $parser = $reflectionProperty->getValue($phpSourceAnalyzer);

        $phpSourceAnalyzer->analyze(new FinderFileInfo($this->temporaryBasePath . '/app/First.php', 'app', 'app/First.php'));
        $phpSourceAnalyzer->analyze(new FinderFileInfo($this->temporaryBasePath . '/app/Second.php', 'app', 'app/Second.php'));

        self::assertSame($parser, $reflectionProperty->getValue($phpSourceAnalyzer));
    }

    private function resultWithAdvisories(): \Dgtlss\Warden\ValueObjects\AuditResult
    {
        $this->write('app/Debug.php', '<?php dd("x");');
        $this->write('resources/views/output.blade.php', '{!! $body !!}');

        return $this->service()->run(new AuditContext());
    }

    private function finding(string $id): \Dgtlss\Warden\ValueObjects\Finding
    {
        foreach ($this->service()->run(new AuditContext())->findings as $finding) {
            if ($finding->id === $id) {
                return $finding;
            }
        }

        self::fail(sprintf('Finding %s was not produced.', $id));
    }

    private function service(): SourceAuditService
    {
        return $this->app->make(SourceAuditService::class);
    }

    private function write(string $relative, string $contents): void
    {
        $path = $this->temporaryBasePath . '/' . $relative;
        if (!is_dir(dirname($path))) {
            mkdir(dirname($path), 0777, true);
        }

        file_put_contents($path, $contents);
    }
}
