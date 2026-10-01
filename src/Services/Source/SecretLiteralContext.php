<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services\Source;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\Parser;
use PhpParser\ParserFactory;

final class SecretLiteralContext
{
    private readonly Parser $parser;

    public function __construct()
    {
        $this->parser = (new ParserFactory())->createForNewestSupportedVersion();
    }

    /** @return array<int, true> */
    public function nonSecretLiteralOffsets(string $contents, string $path): array
    {
        if (!str_ends_with($path, '.php')) {
            return [];
        }

        try {
            $nodes = $this->parser->parse($contents) ?? [];
            $nodes = (new NodeTraverser(new NameResolver()))->traverse($nodes);
        } catch (Error) {
            // Unrecognised context must not suppress a possible credential.
            return [];
        }

        $offsets = [];
        $nodeFinder = new NodeFinder();
        foreach ($nodeFinder->findInstanceOf($nodes, Node\Expr\CallLike::class) as $callLike) {
            $position = $this->validationRulesPosition($callLike);
            if ($position === null) {
                continue;
            }

            $this->ignoreArrayValues($callLike->getArg('rules', $position)?->value, $offsets);
        }

        foreach ($nodeFinder->findInstanceOf($nodes, Node\Stmt\Class_::class) as $class) {
            if ($class->extends?->toString() !== \Illuminate\Foundation\Http\FormRequest::class) {
                continue;
            }

            foreach ($class->getMethods() as $method) {
                if (strtolower($method->name->toString()) !== 'rules') {
                    continue;
                }

                foreach ($method->stmts ?? [] as $statement) {
                    $this->ignoreReturnedArrays($statement, $offsets);
                }
            }
        }

        if (preg_match('#^(?:resources/)?lang/#', str_replace('\\', '/', $path)) === 1) {
            foreach ($nodes as $node) {
                if ($node instanceof Node\Stmt\Return_) {
                    $this->ignoreArrayValues($node->expr, $offsets);
                }
            }
        }

        return $offsets;
    }

    private function validationRulesPosition(Node\Expr\CallLike $callLike): ?int
    {
        if ($callLike instanceof Node\Expr\MethodCall && $callLike->name instanceof Node\Identifier) {
            return match (strtolower($callLike->name->toString())) {
                'validate' => 0,
                'validatewithbag' => 1,
                default => null,
            };
        }

        if ($callLike instanceof Node\Expr\StaticCall && $callLike->class instanceof Node\Name
            && in_array($callLike->class->toString(), ['Validator', \Illuminate\Support\Facades\Validator::class], true)
            && $callLike->name instanceof Node\Identifier && strtolower($callLike->name->toString()) === 'make') {
            return 1;
        }

        if ($callLike instanceof Node\Expr\FuncCall && $callLike->name instanceof Node\Name && $callLike->name->toString() === 'validator') {
            return 1;
        }

        return null;
    }

    /** @param array<int, true> $offsets */
    private function ignoreReturnedArrays(Node $node, array &$offsets): void
    {
        if ($node instanceof Node\FunctionLike || $node instanceof Node\Stmt\ClassLike) {
            return;
        }

        if ($node instanceof Node\Stmt\Return_) {
            $this->ignoreArrayValues($node->expr, $offsets);

            return;
        }

        foreach ($node->getSubNodeNames() as $name) {
            $child = $node->$name;
            if ($child instanceof Node) {
                $this->ignoreReturnedArrays($child, $offsets);
            } elseif (is_array($child)) {
                foreach ($child as $nested) {
                    if ($nested instanceof Node) {
                        $this->ignoreReturnedArrays($nested, $offsets);
                    }
                }
            }
        }
    }

    /** @param array<int, true> $offsets */
    private function ignoreArrayValues(?Node\Expr $expr, array &$offsets): void
    {
        if (!$expr instanceof Node\Expr\Array_) {
            return;
        }

        foreach ($expr->items as $item) {
            if ($item->value instanceof Node\Scalar\String_) {
                $offsets[$item->value->getStartFilePos()] = true;
            } elseif ($item->value instanceof Node\Expr\Array_) {
                $this->ignoreArrayValues($item->value, $offsets);
            }
        }
    }
}
