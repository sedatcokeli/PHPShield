<?php

namespace PHPShield\Visitor;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

class TaintVisitor extends NodeVisitorAbstract
{
    private $taintedVars = [];
    private $vulnerabilities = [];
    
    // TaintVisitor.php

public function enterNode(Node $node)
{
    $line = $node->getStartLine();

    // SOURCE — burası enterNode'da kalabilir
    if ($node instanceof Node\Expr\ArrayDimFetch) {
        if ($node->var instanceof Node\Expr\Variable) {
            $varName = $node->var->name;
            if (in_array($varName, ['_GET', '_POST', '_REQUEST', '_COOKIE'])) {
                $this->taintedVars[$varName] = true;
                echo "[DEBUG] Source: \${$varName} tainted at line $line\n";
            }
        }
    }

    // SINK: Echo — enterNode'da kalabilir, propagation leaveNode'da olacak
    if ($node instanceof Node\Stmt\Echo_) {
        foreach ($node->exprs as $expr) {
            if ($this->isTainted($expr)) {
                $this->vulnerabilities[] = [
                    'line' => $line,
                    'type' => 'XSS',
                    'severity' => 'HIGH',
                    'description' => 'User input printed directly without sanitization'
                ];
                echo "[DEBUG] XSS found at line $line\n";
            }
        }
    }

    // SINK: Dangerous functions
    if ($node instanceof Node\Expr\FuncCall) {
        if ($node->name instanceof Node\Name) {
            $funcName = $node->name->toString();
            $dangerous = ['system', 'exec', 'shell_exec', 'passthru', 'eval'];
            if (in_array($funcName, $dangerous)) {
                foreach ($node->args as $arg) {
                    if ($this->isTainted($arg->value)) {
                        $this->vulnerabilities[] = [
                            'line'        => $line,
                            'type'        => 'RCE',
                            'severity'    => 'CRITICAL',
                            'description' => "User input passed to {$funcName}()"
                        ];
                        echo "[DEBUG] RCE found at line $line\n";
                    }
                }
            }
        }
    }

    return null;
}

public function leaveNode(Node $node)
{
    // PROPAGATION — child'lar ziyaret edildikten sonra çalışır
    // Bu noktada $_GET zaten taintedVars'da
    if ($node instanceof Node\Expr\Assign) {
        if (!($node->var instanceof Node\Expr\Variable)) {
            return null;
        }

        $leftVar = $node->var->name;

        if ($this->isTainted($node->expr)) {
            if (!isset($this->taintedVars[$leftVar])) {
                $this->taintedVars[$leftVar] = true;
                echo "[DEBUG] Propagated: \${$leftVar} tainted at line "
                    . $node->getStartLine() . "\n";
            }
        }
    }

    return null;
}
    
    private function isTainted($expr): bool
    {
        // Variable: $id
        if ($expr instanceof Node\Expr\Variable) {
            $varName = $expr->name;
            if (in_array($varName, $this->taintedVars)) {
                echo "[DEBUG] Check: \${$varName} is tainted\n";
                return true;
            }
        }
        
        // ArrayDimFetch: $_GET['id']
        if ($expr instanceof Node\Expr\ArrayDimFetch) {
            if ($expr->var instanceof Node\Expr\Variable) {
                $varName = $expr->var->name;
                if (in_array($varName, $this->taintedVars)) {
                    echo "[DEBUG] Check: \${$varName} is tainted (array access)\n";
                    return true;
                }
            }
        }
        
        return false;
    }
    
    public function getVulnerabilities(): array
    {
        return $this->vulnerabilities;
    }
    
    public function getTaintedVars(): array
    {
        return $this->taintedVars;
    }
}
