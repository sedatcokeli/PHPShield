<?php

namespace PHPShield\Visitor;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

class TaintVisitor extends NodeVisitorAbstract
{
    private $taintedVars = [];
    private $vulnerabilities = [];
    
    // EVRENSEL SQL Injection sink'leri (tüm olası metodlar)
    private $sqlSinks = [
        // Fonksiyonlar
        'mysqli_query', 'mysql_query', 'pg_query', 'sqlsrv_query', 'odbc_exec',
        // PDO
        'query', 'exec', 'prepare',
        // ORM / Wrapper (yaygın isimler)
        'select', 'insert', 'update', 'delete', 'find', 'findOne', 'findAll',
        'get', 'fetch', 'fetchAll', 'fetchColumn', 'execute'
    ];
    
    private $commandSinks = ['system', 'exec', 'shell_exec', 'passthru', 'proc_open', 'popen'];
    private $codeExecSinks = ['eval', 'assert', 'create_function', 'preg_replace'];
    
    public function enterNode(Node $node)
    {
        $line = $node->getStartLine();
        
        // ============ SOURCE ============
        if ($node instanceof Node\Expr\ArrayDimFetch) {
            if ($node->var instanceof Node\Expr\Variable) {
                $varName = $node->var->name;
                if (in_array($varName, ['_GET', '_POST', '_REQUEST', '_COOKIE', '_SERVER', '_ENV', '_FILES'])) {
                    $this->taintedVars[$varName] = true;
                    echo "[DEBUG] Source: \${$varName} tainted at line $line\n";
                }
            }
        }
        
        // ============ XSS ============
        if ($node instanceof Node\Stmt\Echo_ || $node instanceof Node\Expr\Print_) {
            $exprs = ($node instanceof Node\Stmt\Echo_) ? $node->exprs : [$node->expr];
            foreach ($exprs as $expr) {
                if ($this->isTainted($expr)) {
                    $this->addVulnerability($line, 'XSS', 'HIGH', 'User input printed directly without sanitization');
                    echo "[DEBUG] XSS found at line $line\n";
                }
            }
        }
        
        // ============ FUNCTION CALLS ============
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            $funcName = strtolower($node->name->toString());
            
            if (in_array($funcName, $this->sqlSinks)) {
                foreach ($node->args as $arg) {
                    if ($this->isTainted($arg->value)) {
                        $this->addVulnerability($line, 'SQL_INJECTION', 'CRITICAL', 
                            "Potential SQL Injection in {$funcName}() - User input in query");
                        echo "[DEBUG] SQL Injection found at line $line in {$funcName}()\n";
                        break;
                    }
                }
            }
            
            if (in_array($funcName, $this->commandSinks)) {
                foreach ($node->args as $arg) {
                    if ($this->isTainted($arg->value)) {
                        $this->addVulnerability($line, 'COMMAND_INJECTION', 'CRITICAL', 
                            "Potential Command Injection in {$funcName}()");
                        echo "[DEBUG] Command Injection found at line $line in {$funcName}()\n";
                        break;
                    }
                }
            }
            
            if (in_array($funcName, $this->codeExecSinks)) {
                foreach ($node->args as $arg) {
                    if ($this->isTainted($arg->value)) {
                        $this->addVulnerability($line, 'RCE', 'CRITICAL', 
                            "Potential Remote Code Execution in {$funcName}()");
                        echo "[DEBUG] RCE found at line $line in {$funcName}()\n";
                        break;
                    }
                }
            }
        }
        
        // ============ METHOD CALLS (OOP - EVRENSEL) ============
        if ($node instanceof Node\Expr\MethodCall) {
            $methodName = $node->name->name;
            
            // SQL Injection kontrolü
            if (in_array($methodName, $this->sqlSinks)) {
                foreach ($node->args as $arg) {
                    if ($this->isTainted($arg->value)) {
                        $this->addVulnerability($line, 'SQL_INJECTION', 'CRITICAL', 
                            "Potential SQL Injection in ->{$methodName}() - User input in query");
                        echo "[DEBUG] SQL Injection found at line $line in ->{$methodName}()\n";
                        break;
                    }
                }
            }
            
            // XSS kontrolü (echo benzeri metodlar)
            if (in_array($methodName, ['echo', 'print', 'write', 'output'])) {
                foreach ($node->args as $arg) {
                    if ($this->isTainted($arg->value)) {
                        $this->addVulnerability($line, 'XSS', 'HIGH', 
                            "Potential XSS in ->{$methodName}()");
                        echo "[DEBUG] XSS found at line $line in ->{$methodName}()\n";
                        break;
                    }
                }
            }
        }
        
        // ============ STATIC CALLS (EVRENSEL) ============
        if ($node instanceof Node\Expr\StaticCall) {
            $className = $node->class->toString();
            $methodName = $node->name->name;
            
            // Tüm static DB/Model metodlarını kontrol et
            if (in_array($methodName, $this->sqlSinks)) {
                foreach ($node->args as $argIndex => $arg) {
                    $argValue = $arg->value;
                    
                    // String concatenation
                    if ($argValue instanceof Node\Expr\BinaryOp\Concat) {
                        $this->addVulnerability($line, 'SQL_INJECTION', 'CRITICAL', 
                            "Potential SQL Injection in {$className}::{$methodName}() - String concatenation");
                        echo "[DEBUG] SQL Injection found at line $line in {$className}::{$methodName}()\n";
                        break;
                    }
                    
                    // Tainted variable
                    if ($argValue instanceof Node\Expr\Variable) {
                        $varName = $argValue->name;
                        if (isset($this->taintedVars[$varName])) {
                            $this->addVulnerability($line, 'SQL_INJECTION', 'CRITICAL', 
                                "Potential SQL Injection in {$className}::{$methodName}() - Tainted variable \${$varName}");
                            echo "[DEBUG] SQL Injection found at line $line in {$className}::{$methodName}()\n";
                            break;
                        }
                    }
                    
                    // String interpolation
                    if ($argValue instanceof Node\Scalar\String_) {
                        if (preg_match('/\$[a-zA-Z_][a-zA-Z0-9_]*/', $argValue->value)) {
                            $this->addVulnerability($line, 'SQL_INJECTION', 'CRITICAL', 
                                "Potential SQL Injection in {$className}::{$methodName}() - Variable interpolation");
                            echo "[DEBUG] SQL Injection found at line $line in {$className}::{$methodName}()\n";
                            break;
                        }
                    }
                    
                    // Direkt tainted check
                    if ($this->isTainted($argValue)) {
                        $this->addVulnerability($line, 'SQL_INJECTION', 'CRITICAL', 
                            "Potential SQL Injection in {$className}::{$methodName}()");
                        echo "[DEBUG] SQL Injection found at line $line in {$className}::{$methodName}()\n";
                        break;
                    }
                }
            }
        }
        
        // ============ LFI/RFI ============
        if ($node instanceof Node\Expr\Include_) {
            if ($this->isTainted($node->expr)) {
                $this->addVulnerability($line, 'LFI_RFI', 'CRITICAL', 'Local/Remote File Inclusion vulnerability');
                echo "[DEBUG] LFI/RFI found at line $line\n";
            }
        }
        
        return null;
    }
    
    public function leaveNode(Node $node)
    {
        // ============ PROPAGATION ============
        
        if ($node instanceof Node\Expr\Assign) {
            if (!($node->var instanceof Node\Expr\Variable)) {
                return null;
            }
            
            $leftVar = $node->var->name;
            $rightExpr = $node->expr;
            
            if ($this->isTainted($rightExpr)) {
                if (!isset($this->taintedVars[$leftVar])) {
                    $this->taintedVars[$leftVar] = true;
                    echo "[DEBUG] Propagated: \${$leftVar} tainted at line " . $node->getStartLine() . "\n";
                }
            }
            
            // String concatenation
            if ($rightExpr instanceof Node\Expr\BinaryOp\Concat) {
                if ($this->isTainted($rightExpr->left) || $this->isTainted($rightExpr->right)) {
                    if (!isset($this->taintedVars[$leftVar])) {
                        $this->taintedVars[$leftVar] = true;
                        echo "[DEBUG] Propagated (concat): \${$leftVar} tainted at line " . $node->getStartLine() . "\n";
                    }
                }
            }
            
            // String interpolation
            if ($rightExpr instanceof Node\Scalar\String_) {
                if (preg_match('/\$[a-zA-Z_][a-zA-Z0-9_]*/', $rightExpr->value)) {
                    if (!isset($this->taintedVars[$leftVar])) {
                        $this->taintedVars[$leftVar] = true;
                        echo "[DEBUG] Propagated (interpolated): \${$leftVar} tainted at line " . $node->getStartLine() . "\n";
                    }
                }
            }
            
            // Function call return değeri
            if ($rightExpr instanceof Node\Expr\FuncCall) {
                $funcName = $rightExpr->name instanceof Node\Name ? $rightExpr->name->toString() : '';
                $safeFuncs = ['htmlspecialchars', 'strip_tags', 'intval', 'floatval', 'trim', 'mysqli_real_escape_string'];
                if (!in_array($funcName, $safeFuncs)) {
                    if (!isset($this->taintedVars[$leftVar])) {
                        $this->taintedVars[$leftVar] = true;
                        echo "[DEBUG] Propagated (func return): \${$leftVar} tainted at line " . $node->getStartLine() . "\n";
                    }
                }
            }
        }
        
        return null;
    }
    
    private function isTainted($expr): bool
    {
        // Variable
        if ($expr instanceof Node\Expr\Variable) {
            $varName = $expr->name;
            if (isset($this->taintedVars[$varName])) {
                echo "[DEBUG] Check: \${$varName} is tainted\n";
                return true;
            }
        }
        
        // Array access
        if ($expr instanceof Node\Expr\ArrayDimFetch) {
            if ($expr->var instanceof Node\Expr\Variable) {
                $varName = $expr->var->name;
                if (in_array($varName, ['_GET', '_POST', '_REQUEST', '_COOKIE'])) {
                    echo "[DEBUG] Check: \${$varName} is tainted (superglobal)\n";
                    return true;
                }
                if (isset($this->taintedVars[$varName])) {
                    echo "[DEBUG] Check: \${$varName}[] is tainted\n";
                    return true;
                }
            }
        }
        
        // String concatenation
        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            if ($this->isTainted($expr->left) || $this->isTainted($expr->right)) {
                echo "[DEBUG] Check: String concatenation contains tainted data\n";
                return true;
            }
        }
        
        return false;
    }
    
    private function addVulnerability($line, $type, $severity, $description)
    {
        $this->vulnerabilities[] = [
            'line' => $line,
            'type' => $type,
            'severity' => $severity,
            'description' => $description
        ];
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