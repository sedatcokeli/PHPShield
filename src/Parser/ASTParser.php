<?php

namespace PHPShield\Parser;

use PhpParser\ParserFactory;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\PrettyPrinter\Standard;

class ASTParser
{
    private $parser;
    private $traverser;
    private $prettyPrinter;
    private $ast;
    private $code;
    
    public function __construct()
    {
        $factory = new ParserFactory();
        $this->parser = $factory->create(ParserFactory::PREFER_PHP7);
        $this->traverser = new NodeTraverser();
        $this->traverser->addVisitor(new NameResolver());
        $this->prettyPrinter = new Standard();
    }
    
    public function parse(string $code): ?array
    {
        $this->code = $code;
        
        try {
            $this->ast = $this->parser->parse($code);
            if ($this->ast) {
                $this->ast = $this->traverser->traverse($this->ast);
            }
            return $this->ast;
        } catch (\Exception $e) {
            return null;
        }
    }
    
    public function parseFile(string $filePath): ?array
    {
        if (!file_exists($filePath)) {
            throw new \Exception("File not found: $filePath");
        }
        
        $code = file_get_contents($filePath);
        return $this->parse($code);
    }
    
    public function getAST(): ?array
    {
        return $this->ast;
    }
    
    public function getCode(): string
    {
        return $this->code;
    }
    
    public function getPrettyPrint($ast = null): string
    {
        return $this->prettyPrinter->prettyPrint($ast ?? $this->ast);
    }
}
