<?php
require_once 'vendor/autoload.php';

use PhpParser\ParserFactory;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;

class DebugVisitor extends NodeVisitorAbstract
{
    public function enterNode($node)
    {
        $line = $node->getStartLine();
        
        if ($node instanceof Node\Stmt\Expression) {
            echo "\n*** EXPRESSION at line $line ***\n";
            if ($node->expr instanceof Node\Expr\Assign) {
                echo "  This is an ASSIGN inside Expression!\n";
                $assign = $node->expr;
                if ($assign->var instanceof Node\Expr\Variable) {
                    echo "  Left: $" . $assign->var->name . "\n";
                }
            }
        }
        
        if ($node instanceof Node\Expr\Variable) {
            echo "Variable: $" . $node->name . " at line $line\n";
        }
        
        if ($node instanceof Node\Expr\ArrayDimFetch) {
            echo "ArrayDimFetch at line $line\n";
            if ($node->var instanceof Node\Expr\Variable) {
                echo "  Array: $" . $node->var->name . "\n";
            }
        }
    }
}

$code = file_get_contents('test4.php');
$parser = (new ParserFactory())->create(ParserFactory::PREFER_PHP7);
$ast = $parser->parse($code);

$traverser = new NodeTraverser();
$traverser->addVisitor(new DebugVisitor());
$traverser->traverse($ast);
