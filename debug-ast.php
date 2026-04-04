<?php
require_once 'vendor/autoload.php';

use PhpParser\ParserFactory;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;

class DebugVisitor extends NodeVisitorAbstract
{
    public function enterNode($node)
    {
        echo get_class($node) . "\n";
        if (method_exists($node, 'getStartLine')) {
            echo "  Line: " . $node->getStartLine() . "\n";
        }
        if ($node instanceof Node\Expr\Assign) {
            echo "  *** ASSIGN NODE FOUND ***\n";
        }
        if ($node instanceof Node\Expr\Variable) {
            echo "  Variable: " . $node->name . "\n";
        }
    }
}

$code = '<?php $id = $_GET["id"]; echo $id; system($id);';
$parser = (new ParserFactory())->create(ParserFactory::PREFER_PHP7);
$ast = $parser->parse($code);

$traverser = new NodeTraverser();
$traverser->addVisitor(new DebugVisitor());
$traverser->traverse($ast);
