# 🔒 PHPShield - PHP Güvenlik Tarayıcısı

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PHP Version](https://img.shields.io/badge/PHP-7.4%2B-blue)]()

[English](#english) | [Türkçe](#türkçe)

---

# Türkçe

PHP projelerinde SQL Injection, XSS ve diğer güvenlik açıklarını tespit eden **AST + Taint Analysis** tabanlı profesyonel güvenlik tarayıcısı.

## ⚠️ Bu NEDİR / Bu NE DEĞİLDİR

| ✅ Bu BUDUR | ❌ Bu DEĞİLDİR |
|-------------|----------------|
| AST + Taint Analysis tabanlı statik analiz | Tam kapsamlı güvenlik tarayıcısı |
| Bariz güvenlik desenlerini bulur | SAST (Statik Analiz) aracı |
| Junior geliştiriciler için eğitim aracı | Profesyonel sızma testi aracı |
| İlk savunma hattı | Tam güvenlik çözümü |

> **Sonuçları her zaman manuel doğrulayın. Yanlış pozitif/negatif olabilir.**

## ✨ Özellikler

- ✅ AST (Abstract Syntax Tree) tabanlı analiz
- ✅ Taint Tracking (Kaynak → Yayılım → Hassas Nokta)
- ✅ SQL Enjeksiyon tespiti
- ✅ XSS (Cross-Site Scripting) tespiti
- ✅ RCE (Uzaktan Kod Çalıştırma) tespiti
- ✅ LFI/RFI tespiti
- ✅ JSON rapor çıktısı
- ✅ CLI seçenekleri
- ✅ **Tek komutla kurulum**

## 📦 Kurulum (1 Adım!)

```bash
# Proje dizinine indir
wget https://raw.githubusercontent.com/sedatcokeli/php-shield/main/bin/phpShield

# Çalıştırılabilir yap
chmod +x phpShield

# Veya doğrudan PHP ile çalıştır
php phpShield /proje/dizini