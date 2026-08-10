<?php

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr\BinaryOp\Greater;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\LNumber;
use PhpParser\Node\Stmt\ElseIf_;
use PhpParser\Node\Stmt\Expression;
use PhpParser\Node\Stmt\If_;
use Rector\Rector\AbstractRector;

final class RegenerateSessionOnLoginRector extends AbstractRector
{
    public function getNodeTypes(): array
    {
        return [If_::class, ElseIf_::class];
    }

    public function refactor(Node $node): ?Node
    {
        if (!$this->isSuccessfulLoginCondition($node->cond)) {
            return null;
        }

        foreach ($node->stmts as $statement) {
            if (
                $statement instanceof Expression
                && $statement->expr instanceof FuncCall
                && $statement->expr->name instanceof Name
                && $statement->expr->name->toString() === 'session_regenerate_id'
            ) {
                return null;
            }
        }

        array_unshift(
            $node->stmts,
            new Expression(
                new FuncCall(
                    new Name('session_regenerate_id'),
                    [new Arg(new ConstFetch(new Name('true')))]
                )
            )
        );

        return $node;
    }

    private function isSuccessfulLoginCondition(Node $condition): bool
    {
        if (!$condition instanceof Greater || !$condition->right instanceof LNumber) {
            return false;
        }

        if ($condition->right->value !== 0 || !$condition->left instanceof Variable) {
            return false;
        }

        return in_array($condition->left->name, ['counts_loginAdmin', 'counts_loginCustomer'], true);
    }
}
