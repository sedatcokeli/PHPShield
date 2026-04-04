# 🔒 PHPShield – PHP Security Scanner

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)  
[![PHP Version](https://img.shields.io/badge/PHP-7.4%2B-blue)]()

🇹🇷 Türkçe | 🇬🇧 English

---

# 🇹🇷 Türkçe

PHP projelerinde potansiyel güvenlik açıklarını tespit etmek için geliştirilmiş, **AST (Abstract Syntax Tree) ve Taint Analysis** tabanlı hafif bir statik analiz aracıdır.

---

## 🎯 Amaç

PHPShield, geliştiricilerin kod yazım sürecinde erken aşamada güvenlik problemlerini fark etmesini sağlayan bir **ilk savunma hattı** aracıdır.

- Güvenlik farkındalığını artırır  
- Yaygın zafiyetleri erken tespit eder  
- Manuel güvenlik incelemelerine destek olur  

---

## ✨ Özellikler

- ✅ AST (Abstract Syntax Tree) tabanlı analiz  
- ✅ Taint Tracking (Kaynak → Yayılım → Sink)  
- ✅ SQL Injection tespiti  
- ✅ XSS (Cross-Site Scripting) tespiti  
- ✅ RCE (Remote Code Execution) tespiti  
- ✅ LFI / RFI tespiti  
- ✅ JSON rapor çıktısı  
- ✅ CLI kullanımı  
- ✅ Tek dosya, hızlı kurulum  

---

## 📦 Kurulum

```bash
wget https://raw.githubusercontent.com/sedatcokeli/php-shield/main/bin/phpShield
chmod +x phpShield

# veya
php phpShield /proje/dizini
```

---

## 🚀 Kullanım

```bash
php phpShield /path/to/project
```

---

## 📌 Kapsam ve Sınırlamalar

PHPShield bir **statik analiz aracıdır** ve aşağıdakileri yapmaz:

- Çalışan kodu execute etmez  
- Dinamik analiz (DAST) yapmaz  
- Exploit üretmez veya doğrulamaz  

> ⚠️ Tespit edilen bulgular manuel olarak doğrulanmalıdır.  
> Yanlış pozitif ve yanlış negatif sonuçlar oluşabilir.

---

## ⚖️ Yasal Uyarı

Bu yazılım yalnızca **yetkili güvenlik testleri ve eğitim amaçlı** kullanılmalıdır.

Bu aracı kullanarak şunları kabul etmiş olursunuz:

- Yalnızca sahip olduğunuz veya açık izin aldığınız sistemlerde test yapacağınızı  
- Tüm kullanım sorumluluğunun size ait olduğunu  

Yazar, bu yazılımın kötüye kullanımından doğabilecek hiçbir zarardan sorumlu değildir.

---

# 🇬🇧 English

PHPShield is a lightweight **AST-based static analysis tool** designed to detect potential security vulnerabilities in PHP projects.

---

## 🎯 Purpose

PHPShield helps developers identify security issues early in the development lifecycle.

- Improves security awareness  
- Detects common vulnerability patterns  
- Supports manual security reviews  

---

## ✨ Features

- ✅ AST (Abstract Syntax Tree) based analysis  
- ✅ Taint tracking (Source → Propagation → Sink)  
- ✅ SQL Injection detection  
- ✅ XSS (Cross-Site Scripting) detection  
- ✅ RCE (Remote Code Execution) detection  
- ✅ LFI / RFI detection  
- ✅ JSON reporting  
- ✅ CLI interface  
- ✅ Single-file, easy setup  

---

## 📦 Installation

```bash
wget https://raw.githubusercontent.com/sedatcokeli/php-shield/main/bin/phpShield
chmod +x phpShield

# or
php phpShield /path/to/project
```

---

## 🚀 Usage

```bash
php phpShield /path/to/project
```

---

## 📌 Scope & Limitations

PHPShield is a **static analysis tool** and does NOT:

- Execute application code  
- Perform dynamic analysis (DAST)  
- Guarantee exploitability of findings  

> ⚠️ All findings should be manually verified.  
> False positives and false negatives may occur.

---

## ⚖️ Legal Notice

This software is intended for **authorized security testing and educational purposes only**.

By using this tool, you agree that:

- You will only test systems you own or have explicit permission to test  
- You are solely responsible for your actions  

The author assumes no liability for any misuse or damage caused by this software.

---