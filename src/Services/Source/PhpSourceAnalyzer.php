<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services\Source;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\RulePolicy;
use Dgtlss\Warden\ValueObjects\AuditError;
use Dgtlss\Warden\ValueObjects\Finding;
use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard;
use Symfony\Component\Finder\SplFileInfo;

final class PhpSourceAnalyzer
{
    private readonly Parser $parser;

    public function __construct(private readonly RulePolicy $rulePolicy)
    {
        $this->parser = (new ParserFactory())->createForNewestSupportedVersion();
    }

    /** @return array{findings: list<Finding>, errors: list<AuditError>} */
    public function analyze(SplFileInfo $file): array
    {
        $path = ltrim(str_replace(base_path(), '', $file->getRealPath()), DIRECTORY_SEPARATOR);

        try {
            $nodes = $this->parser->parse($file->getContents());
        } catch (Error $error) {
            return [
                'findings' => [],
                'errors' => [new AuditError('source', 'parse_error', sprintf('%s: %s', $path, $error->getMessage()))],
            ];
        }

        if ($nodes === null) {
            return ['findings' => [], 'errors' => []];
        }

        $securityNodeVisitor = new SecurityNodeVisitor($path, $this->rulePolicy);
        $nodeTraverser = new NodeTraverser();
        $nodeTraverser->addVisitor($securityNodeVisitor);
        $nodeTraverser->traverse($nodes);

        return ['findings' => $securityNodeVisitor->findings(), 'errors' => []];
    }
}

/** @internal */
final class SecurityNodeVisitor extends NodeVisitorAbstract
{
    /** @var list<Finding> */
    private array $findings = [];

    /** @var list<array<string, true>> */
    private array $taintScopes = [[]];

    private readonly Standard $standard;

    public function __construct(private readonly string $path, private readonly RulePolicy $rulePolicy)
    {
        $this->standard = new Standard();
    }

    /** @return list<Finding> */
    public function findings(): array
    {
        return $this->findings;
    }

    public function enterNode(Node $node): ?int
    {
        if ($node instanceof Node\FunctionLike) {
            $this->taintScopes[] = [];
        }

        if ($node instanceof Node\Expr\Assign && $node->var instanceof Node\Expr\Variable && is_string($node->var->name)) {
            if ($this->isTainted($node->expr)) {
                $this->taintScopes[$this->scopeIndex()][$node->var->name] = true;
            } else {
                unset($this->taintScopes[$this->scopeIndex()][$node->var->name]);
            }

            if ($node->expr instanceof Node\Expr\FuncCall
                && in_array($this->name($node->expr->name), ['rand', 'mt_rand', 'uniqid'], true)
                && preg_match('/token|secret|reset|csrf|nonce|salt|password|otp|key/i', $node->var->name) === 1) {
                $this->add('source.php.insecure-rng-context', 'Non-cryptographic randomness appears in a security context', Severity::Medium, 'A secret-named value is generated with a predictable randomness function.', 'Use random_bytes(), random_int(), or Str::random().', $node, false);
            }
        }

        if ($node instanceof Node\Expr\FuncCall) {
            $this->inspectFunctionCall($node);
        } elseif ($node instanceof Node\Expr\StaticCall) {
            $this->inspectStaticCall($node);
        } elseif ($node instanceof Node\Expr\MethodCall) {
            $this->inspectMethodCall($node);
        } elseif ($node instanceof Node\Expr\New_) {
            $this->inspectNew($node);
        } elseif ($node instanceof Node\Stmt\Echo_) {
            $this->inspectEcho($node);
        } elseif ($node instanceof Node\Expr\Print_) {
            $this->addTaintedFinding('source.php.xss-tainted-output', $node->expr, $node, 'User-controlled input is emitted without escaping', Severity::High, 'Escape output with e()/htmlspecialchars() or return a framework response that encodes data safely.');
        } elseif ($node instanceof Node\Expr\Include_) {
            $this->addTaintedFinding('source.php.path-traversal', $node->expr, $node, 'User-controlled path reaches include/require', Severity::High, 'Resolve the path against an allowlisted directory and verify containment before loading it.');
        } elseif ($node instanceof Node\Stmt\Property) {
            $this->inspectProperty($node);
        }

        return null;
    }

    public function leaveNode(Node $node): null
    {
        if ($node instanceof Node\FunctionLike) {
            array_pop($this->taintScopes);
        }

        return null;
    }

    private function inspectFunctionCall(Node\Expr\FuncCall $funcCall): void
    {
        $name = $this->name($funcCall->name);
        $first = $this->argument($funcCall->args, 0);

        if (in_array($name, ['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen'], true) && $first instanceof Node\Expr) {
            $this->addTaintedFinding('source.php.command-tainted-input', $first, $funcCall, 'User-controlled input reaches a shell command', Severity::Critical, 'Use Symfony Process argument arrays and never concatenate request data into a shell command.');
        }

        if ($name === 'unserialize' && $first instanceof Node\Expr && !$this->hasSafeAllowedClasses($funcCall)) {
            $this->addTaintedFinding('source.php.unsafe-deserialization', $first, $funcCall, 'User-controlled input reaches unserialize()', Severity::High, 'Use JSON or pass allowed_classes => false after validating the payload.');
        }

        if (in_array($name, ['file_get_contents', 'fopen', 'readfile', 'file_put_contents'], true) && $first instanceof Node\Expr) {
            $this->addTaintedFinding('source.php.path-traversal', $first, $funcCall, 'User-controlled path reaches a filesystem operation', Severity::High, 'Resolve the path beneath an allowlisted root and reject traversal before accessing it.');
        }

        if ($name === 'redirect' && $first instanceof Node\Expr) {
            $this->addTaintedFinding('source.php.open-redirect', $first, $funcCall, 'User-controlled input determines a redirect target', Severity::Medium, 'Redirect to named internal routes or validate the target against an explicit host allowlist.');
        }

        if ($name === 'header' && $first instanceof Node\Expr && str_contains(strtolower($this->normalized($first)), 'location:')) {
            $this->addTaintedFinding('source.php.open-redirect', $first, $funcCall, 'User-controlled input determines a Location header', Severity::Medium, 'Use a named internal route or validate an external destination against an allowlist.');
        }

        if ($name === 'stream_context_create' && $first instanceof Node\Expr\Array_
            && ($this->arrayContainsBoolean($first, ['verify_peer', 'verify_peer_name'], false)
                || $this->arrayContainsBoolean($first, ['allow_self_signed'], true))) {
            $this->add('source.php.tls-verification-disabled', 'TLS certificate verification is disabled', Severity::High, 'The stream context disables peer verification or permits self-signed certificates.', 'Enable peer and peer-name verification and use a trusted certificate authority.', $funcCall);
        }

        $second = $this->argument($funcCall->args, 1);
        $third = $this->argument($funcCall->args, 2);
        if ($name === 'curl_setopt' && $second instanceof \PhpParser\Node\Expr && $third instanceof \PhpParser\Node\Expr) {
            $option = strtoupper($this->name($second));
            if (in_array($option, ['CURLOPT_SSL_VERIFYPEER', 'CURLOPT_SSL_VERIFYHOST'], true) && $this->isFalseLike($third)) {
                $this->add('source.php.tls-verification-disabled', 'TLS certificate verification is disabled', Severity::High, 'Disabling TLS verification permits man-in-the-middle attacks.', 'Remove the override and trust the correct certificate authority.', $funcCall);
            }

            if ($option === 'CURLOPT_URL') {
                $this->addTaintedFinding('source.php.ssrf-tainted-url', $third, $funcCall, 'User-controlled input determines an outbound URL', Severity::High, 'Validate scheme, host, port, DNS result, and redirect destinations against an allowlist.');
            }
        }

        if (str_starts_with($name, 'mcrypt_')) {
            $this->add('source.php.weak-cipher', 'Deprecated mcrypt cipher is used', Severity::High, 'mcrypt is obsolete and does not provide modern authenticated encryption.', 'Use Laravel encryption or libsodium.', $funcCall);
        }

        if (in_array($name, ['openssl_encrypt', 'openssl_decrypt'], true) && $second instanceof \PhpParser\Node\Expr) {
            $cipher = strtolower($this->stringValue($second) ?? '');
            if ($cipher !== '' && preg_match('/(?:^|[-_])(des|3des|rc2|rc4|ecb)(?:$|[-_])/', $cipher) === 1) {
                $this->add('source.php.weak-cipher', 'Weak or unauthenticated cipher is used', Severity::High, sprintf('The configured cipher "%s" is unsuitable for protecting sensitive data.', $cipher), 'Use Laravel encryption or an authenticated AES-GCM/libsodium construction.', $funcCall);
            }
        }

        if (in_array($name, ['dd', 'dump', 'var_dump', 'phpinfo'], true)) {
            $this->add('source.php.debug-call', 'Debug function remains in application source', Severity::Low, sprintf('%s() may disclose application data when executed.', $name), 'Remove the call or ensure it cannot execute outside local development.', $funcCall, false);
        }

        if (in_array($name, ['md5', 'sha1'], true) && $this->hasSecurityContext($funcCall)) {
            $this->add('source.php.weak-hash-context', 'Weak hash appears in a security context', Severity::Medium, sprintf('%s() is not suitable for passwords, signatures, or security tokens.', $name), 'Use password_hash, hash_hmac with SHA-256+, or a framework security primitive.', $funcCall, false);
        }

        if (in_array($name, ['rand', 'mt_rand', 'uniqid'], true) && $this->hasSecurityContext($funcCall)) {
            $this->add('source.php.insecure-rng-context', 'Non-cryptographic randomness appears in a security context', Severity::Medium, sprintf('%s() must not generate secrets or tokens.', $name), 'Use random_bytes(), random_int(), or Str::random().', $funcCall, false);
        }
    }

    private function inspectStaticCall(Node\Expr\StaticCall $staticCall): void
    {
        $class = strtolower($this->name($staticCall->class));
        $method = strtolower($this->name($staticCall->name));
        $first = $this->argument($staticCall->args, 0);

        if ($this->endsWith($class, 'db') && in_array($method, ['select', 'insert', 'update', 'delete', 'statement', 'raw'], true) && $first instanceof Node\Expr && $this->isDynamicString($first)) {
            $this->add('source.php.sql-dynamic-raw', 'Dynamic data is interpolated into raw SQL', Severity::High, 'Raw SQL contains interpolation or concatenation instead of parameter bindings.', 'Use query builder methods or positional/named bindings.', $staticCall);
        }

        if ($this->endsWith($class, 'http') && in_array($method, ['get', 'post', 'put', 'patch', 'delete', 'head', 'send'], true) && $first instanceof Node\Expr) {
            $this->addTaintedFinding('source.php.ssrf-tainted-url', $first, $staticCall, 'User-controlled input determines an outbound URL', Severity::High, 'Validate scheme, host, port, DNS result, and redirects against an allowlist.');
        }

        if ($this->endsWith($class, 'storage') && in_array($method, ['get', 'put', 'move', 'copy', 'delete', 'download', 'readstream', 'writestream'], true) && $first instanceof Node\Expr) {
            $this->addTaintedFinding('source.php.path-traversal', $first, $staticCall, 'User-controlled path reaches Laravel storage', Severity::High, 'Map external identifiers to server-owned paths instead of accepting a path from the request.');
        }

        if (($this->endsWith($class, 'redirect') || $this->endsWith($class, 'redirector')) && in_array($method, ['away', 'to'], true) && $first instanceof Node\Expr) {
            $this->addTaintedFinding('source.php.open-redirect', $first, $staticCall, 'User-controlled input determines a redirect target', Severity::Medium, 'Use named internal routes or an explicit destination allowlist.');
        }

        if ($this->endsWith($class, 'model') && $method === 'unguard') {
            $this->add('source.laravel.mass-assignment-disabled', 'Global mass-assignment protection is disabled', Severity::Medium, 'Model::unguard() permits unrestricted mass assignment for every model.', 'Scope unguarding narrowly to trusted seed/import code or use explicit fillable attributes.', $staticCall, false);
        }

        if ($this->endsWith($class, 'log') && in_array($method, ['debug', 'info', 'notice', 'warning', 'error'], true) && $this->hasSecurityContext($staticCall)) {
            $this->add('source.php.sensitive-log', 'Sensitive value may be written to logs', Severity::Medium, 'A log statement references request or secret-named data.', 'Log an opaque identifier and redact credentials, tokens, and personal data.', $staticCall, false);
        }

        if ($this->endsWith($class, 'http') && $method === 'withoutverifying') {
            $this->add('source.php.tls-verification-disabled', 'TLS certificate verification is disabled', Severity::High, 'Http::withoutVerifying() permits man-in-the-middle attacks.', 'Remove withoutVerifying() and configure the correct CA certificate.', $staticCall);
        }

        if ($this->endsWith($class, 'http') && $method === 'withoptions' && $first instanceof Node\Expr\Array_ && $this->arrayBoolean($first, 'verify') === false) {
            $this->add('source.php.tls-verification-disabled', 'TLS certificate verification is disabled', Severity::High, 'The Laravel HTTP client is configured with verify=false.', 'Remove the override and configure the correct CA certificate.', $staticCall);
        }
    }

    private function inspectMethodCall(Node\Expr\MethodCall $methodCall): void
    {
        $method = strtolower($this->name($methodCall->name));
        $first = $this->argument($methodCall->args, 0);

        if (in_array($method, ['whereraw', 'selectraw', 'orderbyraw', 'havingraw', 'groupbyraw', 'fromraw'], true) && $first instanceof Node\Expr && $this->isDynamicString($first)) {
            $this->add('source.php.sql-dynamic-raw', 'Dynamic data is interpolated into raw SQL', Severity::High, 'A raw query-builder expression contains interpolation or concatenation.', 'Use the method binding argument or a structured query-builder API.', $methodCall);
        }

        if (in_array($method, ['away', 'to'], true) && $first instanceof Node\Expr && ($method === 'away' || str_contains(strtolower($this->normalized($methodCall->var)), 'redirect'))) {
            $this->addTaintedFinding('source.php.open-redirect', $first, $methodCall, 'User-controlled input determines a redirect target', Severity::Medium, 'Use a named route or validate an external destination against an allowlist.');
        }

        if (in_array($method, ['request', 'get', 'post', 'put', 'patch', 'delete', 'head'], true)
            && preg_match('/client|guzzle|http/i', $this->normalized($methodCall->var)) === 1) {
            $url = $method === 'request' ? $this->argument($methodCall->args, 1) : $first;
            if ($url instanceof Node\Expr) {
                $this->addTaintedFinding('source.php.ssrf-tainted-url', $url, $methodCall, 'User-controlled input determines an outbound URL', Severity::High, 'Validate scheme, host, port, DNS result, and redirects against an allowlist.');
            }
        }

        if ($method === 'withoutverifying') {
            $this->add('source.php.tls-verification-disabled', 'TLS certificate verification is disabled', Severity::High, 'withoutVerifying() permits man-in-the-middle attacks.', 'Remove the override and configure the correct CA certificate.', $methodCall);
        }

        if ($method === 'withoptions' && $first instanceof Node\Expr\Array_ && $this->arrayBoolean($first, 'verify') === false) {
            $this->add('source.php.tls-verification-disabled', 'TLS certificate verification is disabled', Severity::High, 'An HTTP client is configured with verify=false.', 'Remove the override and configure the correct CA certificate.', $methodCall);
        }

        if ($method === 'withoutmiddleware' && $first instanceof Node\Expr && preg_match('/(?:VerifyCsrfToken|ValidateCsrfToken|PreventRequestForgery)/i', $this->normalized($first)) === 1) {
            $this->add('source.laravel.csrf-disabled', 'Laravel request-forgery middleware is explicitly disabled', Severity::Critical, 'Application code removes Laravel CSRF/request-forgery protection.', 'Remove the exclusion or scope it to a narrowly reviewed webhook route with alternative verification.', $methodCall);
        }
    }

    private function inspectNew(Node\Expr\New_ $new): void
    {
        if (!$new->class instanceof Node\Name || !$this->endsWith(strtolower($new->class->toString()), 'client')) {
            return;
        }

        $first = $this->argument($new->args, 0);
        if ($first instanceof Node\Expr\Array_ && $this->arrayBoolean($first, 'verify') === false) {
            $this->add('source.php.tls-verification-disabled', 'TLS certificate verification is disabled', Severity::High, 'An HTTP client is constructed with verify=false.', 'Remove the override and configure the correct CA certificate.', $new);
        }
    }

    private function inspectEcho(Node\Stmt\Echo_ $echo): void
    {
        foreach ($echo->exprs as $expr) {
            $this->addTaintedFinding('source.php.xss-tainted-output', $expr, $echo, 'User-controlled input is emitted without escaping', Severity::High, 'Escape output with e()/htmlspecialchars() or return a framework response that encodes data safely.');
        }
    }

    private function inspectProperty(Node\Stmt\Property $property): void
    {
        foreach ($property->props as $prop) {
            if ($prop->name->toString() === 'guarded' && $prop->default instanceof Node\Expr\Array_ && $prop->default->items === []) {
                $this->add('source.laravel.mass-assignment-disabled', 'Model permits every attribute to be mass assigned', Severity::Medium, '$guarded = [] disables Laravel mass-assignment protection for the model.', 'Use explicit fillable attributes or guard sensitive columns.', $property, false);
            }
        }
    }

    private function addTaintedFinding(string $id, Node\Expr $expr, Node $location, string $title, Severity $severity, string $remediation): void
    {
        if ($this->isTainted($expr)) {
            $this->add($id, $title, $severity, 'Request-controlled data reaches a security-sensitive operation without a recognized validation boundary.', $remediation, $location);
        }
    }

    private function add(string $id, string $title, Severity $severity, string $description, string $remediation, Node $node, bool $blocking = true): void
    {
        if (!$this->rulePolicy->enabled($id)) {
            return;
        }

        $this->findings[] = new Finding(
            id: $id,
            source: 'source',
            title: $title,
            severity: $severity,
            description: $description,
            remediation: $remediation,
            path: $this->path,
            line: max(1, $node->getStartLine()),
            blocking: $blocking,
            identity: hash('sha256', $this->normalized($node)),
        );
    }

    private function isTainted(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return in_array($expr->name, ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES'], true)
                || isset($this->taintScopes[$this->scopeIndex()][$expr->name]);
        }

        if ($expr instanceof Node\Expr\ArrayDimFetch && $expr->var instanceof Node\Expr\Variable && is_string($expr->var->name)) {
            return in_array($expr->var->name, ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES'], true) || $this->isTainted($expr->var);
        }

        if ($expr instanceof Node\Expr\PropertyFetch && $expr->var instanceof Node\Expr\Variable && $expr->var->name === 'request') {
            return true;
        }

        if ($expr instanceof Node\Expr\MethodCall) {
            $method = strtolower($this->name($expr->name));
            if (in_array($method, ['input', 'get', 'post', 'query', 'cookie', 'file', 'all', 'only', 'except'], true)
                && (($expr->var instanceof Node\Expr\Variable && $expr->var->name === 'request') || $this->isRequestHelper($expr->var))) {
                return true;
            }

            return $this->isTainted($expr->var);
        }

        if ($expr instanceof Node\Expr\FuncCall) {
            $name = $this->name($expr->name);
            if (in_array($name, ['request', 'input'], true)) {
                return true;
            }

            if (in_array($name, ['e', 'htmlspecialchars', 'htmlentities', 'escapeshellarg', 'escapeshellcmd', 'basename', 'realpath'], true)) {
                return false;
            }

            foreach ($expr->args as $arg) {
                if ($arg instanceof Node\Arg && $this->isTainted($arg->value)) {
                    return true;
                }
            }
        }

        if ($expr instanceof Node\Expr\BinaryOp) {
            return $this->isTainted($expr->left) || $this->isTainted($expr->right);
        }

        if ($expr instanceof Node\Expr\Ternary) {
            return ($expr->if instanceof \PhpParser\Node\Expr && $this->isTainted($expr->if)) || $this->isTainted($expr->else) || $this->isTainted($expr->cond);
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && $this->isTainted($part)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function isRequestHelper(Node\Expr $expr): bool
    {
        return $expr instanceof Node\Expr\FuncCall && $this->name($expr->name) === 'request';
    }

    private function isDynamicString(Node\Expr $expr): bool
    {
        return $expr instanceof Node\Scalar\InterpolatedString
            || ($expr instanceof Node\Expr\BinaryOp\Concat && ($this->containsVariable($expr->left) || $this->containsVariable($expr->right)))
            || ($expr instanceof Node\Expr\FuncCall && $this->name($expr->name) === 'sprintf' && $this->containsVariable($expr));
    }

    private function containsVariable(Node $node): bool
    {
        if ($node instanceof Node\Expr\Variable || $node instanceof Node\Expr\PropertyFetch || $node instanceof Node\Expr\ArrayDimFetch) {
            return true;
        }

        foreach ($node->getSubNodeNames() as $name) {
            $child = $node->$name;
            if ($child instanceof Node && $this->containsVariable($child)) {
                return true;
            }

            if (is_array($child)) {
                foreach ($child as $item) {
                    if ($item instanceof Node && $this->containsVariable($item)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private function hasSafeAllowedClasses(Node\Expr\FuncCall $funcCall): bool
    {
        $options = $this->argument($funcCall->args, 1);
        return $options instanceof Node\Expr\Array_ && $this->arrayBoolean($options, 'allowed_classes') === false;
    }

    private function arrayBoolean(Node\Expr\Array_ $array, string $key): ?bool
    {
        foreach ($array->items as $item) {
            if ($this->stringValue($item->key) !== $key) {
                continue;
            }

            if ($item->value instanceof Node\Expr\ConstFetch) {
                return match (strtolower($item->value->name->toString())) {
                    'true' => true,
                    'false' => false,
                    default => null,
                };
            }
        }

        return null;
    }

    /** @param list<string> $keys */
    private function arrayContainsBoolean(Node\Expr\Array_ $array, array $keys, bool $expected): bool
    {
        foreach ($array->items as $item) {
            $key = $this->stringValue($item->key);
            if ($key !== null && in_array($key, $keys, true) && $this->arrayItemBoolean($item->value) === $expected) {
                return true;
            }

            if ($item->value instanceof Node\Expr\Array_ && $this->arrayContainsBoolean($item->value, $keys, $expected)) {
                return true;
            }
        }

        return false;
    }

    private function arrayItemBoolean(Node\Expr $expr): ?bool
    {
        if (!$expr instanceof Node\Expr\ConstFetch) {
            return null;
        }

        return match (strtolower($expr->name->toString())) {
            'true' => true,
            'false' => false,
            default => null,
        };
    }

    private function isFalseLike(Node\Expr $expr): bool
    {
        return ($expr instanceof Node\Expr\ConstFetch && strtolower($expr->name->toString()) === 'false')
            || ($expr instanceof Node\Scalar\Int_ && $expr->value === 0);
    }

    private function hasSecurityContext(Node $node): bool
    {
        return preg_match('/password|secret|token|signature|hmac|api_?key|auth|nonce|salt|otp|csrf|reset/i', $this->normalized($node)) === 1;
    }

    private function normalized(Node $node): string
    {
        $printed = $node instanceof Node\Expr ? $this->standard->prettyPrintExpr($node) : $this->standard->prettyPrint([$node]);
        return trim((string) preg_replace('/\s+/', ' ', $printed));
    }

    private function stringValue(?Node $node): ?string
    {
        return $node instanceof Node\Scalar\String_ ? $node->value : null;
    }

    private function name(Node|string|null $node): string
    {
        if (is_string($node)) {
            return $node;
        }

        if ($node instanceof Node\Name || $node instanceof Node\Identifier) {
            return $node->toString();
        }

        if ($node instanceof Node\Expr\ClassConstFetch) {
            return $this->name($node->class) . '::' . $this->name($node->name);
        }

        if ($node instanceof Node\Expr\ConstFetch) {
            return $node->name->toString();
        }

        return '';
    }

    private function endsWith(string $value, string $suffix): bool
    {
        return $value === $suffix || str_ends_with($value, '\\' . $suffix);
    }

    private function scopeIndex(): int
    {
        return count($this->taintScopes) - 1;
    }

    /**
     * @param array<Node\Arg|Node\VariadicPlaceholder> $arguments
     */
    private function argument(array $arguments, int $index): ?Node\Expr
    {
        $argument = $arguments[$index] ?? null;

        return $argument instanceof Node\Arg ? $argument->value : null;
    }
}
