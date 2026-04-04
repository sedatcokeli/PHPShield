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
        
        if ($node instanceof Node\Expr\Assign) {
            echo "\n*** ASSIGN NODE at line $line ***\n";
            
            if ($node->var instanceof Node\Expr\Variable) {
                echo "  Left: $" . $node->var->name . "\n";
            }
            
            if ($node->expr instanceof Node\Expr\ArrayDimFetch) {
                echo "  Right: ArrayDimFetch\n";
                if ($node->expr->var instanceof Node\Expr\Variable) {
                    echo "    Array variable: $" . $node->expr->var->name . "\n";
                }
            }
        }
    }
}

// PHP tag ile dene
$code = '<?php $id = $_GET["id"]; ?>';
$parser = (new ParserFactory())->create(ParserFactory::PREFER_PHP7);
$ast = $parser->parse($code);

if (!$ast) {
    echo "Parse error!\n";
    exit(1);
}

$traverser = new NodeTraverser();
$traverser->addVisitor(new DebugVisitor());
$traverser->traverse($ast);

echo "\nDone.\n";
