# VulnPilot Raporu — https://example.com

- **Tarih:** 2026-07-04 09:15 UTC
- **Süre:** 0.7 sn
- **Çalıştırılan araçlar:** http_probe, tls_probe
- **Bulgular:** Medium: 2, Low: 2, Info: 2

## Yönetici Özeti

Toplam 6 bulgu (2 Medium, 2 Low, 2 Info). En yüksek önem: Medium — Eksik güvenlik başlığı: strict-transport-security. Önce yüksek/kritik bulgular giderilmeli.

## Bulgular

### 1. [Medium] Eksik güvenlik başlığı: strict-transport-security
- **Araç:** http_probe
- **Hedef:** https://example.com
- **Açıklama:** HSTS başlığı yok; tarayıcı HTTPS'i zorlamıyor, SSL-stripping riski.
- **Kanıt:**

  ```
  Yanıtta strict-transport-security başlığı yok.
  ```
- **Çözüm:** Strict-Transport-Security: max-age=31536000; includeSubDomains ekle.
- **Kaynaklar:** https://owasp.org/www-project-secure-headers/

### 2. [Medium] Eksik güvenlik başlığı: content-security-policy
- **Araç:** http_probe
- **Hedef:** https://example.com
- **Açıklama:** CSP başlığı yok; XSS ve veri sızıntısına karşı önemli bir katman eksik.
- **Kanıt:**

  ```
  Yanıtta content-security-policy başlığı yok.
  ```
- **Çözüm:** İçeriğe uygun bir Content-Security-Policy tanımla.
- **Kaynaklar:** https://owasp.org/www-project-secure-headers/

### 3. [Low] Eksik güvenlik başlığı: x-frame-options
- **Araç:** http_probe
- **Hedef:** https://example.com
- **Açıklama:** X-Frame-Options yok; clickjacking'e karşı korumasız olabilir.
- **Kanıt:**

  ```
  Yanıtta x-frame-options başlığı yok.
  ```
- **Çözüm:** X-Frame-Options: DENY (veya CSP frame-ancestors) ekle.
- **Kaynaklar:** https://owasp.org/www-project-secure-headers/

### 4. [Low] Eksik güvenlik başlığı: x-content-type-options
- **Araç:** http_probe
- **Hedef:** https://example.com
- **Açıklama:** X-Content-Type-Options yok; MIME-sniffing mümkün.
- **Kanıt:**

  ```
  Yanıtta x-content-type-options başlığı yok.
  ```
- **Çözüm:** X-Content-Type-Options: nosniff ekle.
- **Kaynaklar:** https://owasp.org/www-project-secure-headers/

### 5. [Info] Eksik güvenlik başlığı: referrer-policy
- **Araç:** http_probe
- **Hedef:** https://example.com
- **Açıklama:** Referrer-Policy yok; gezinme bilgisi üçüncü taraflara sızabilir.
- **Kanıt:**

  ```
  Yanıtta referrer-policy başlığı yok.
  ```
- **Çözüm:** Referrer-Policy: strict-origin-when-cross-origin ekle.
- **Kaynaklar:** https://owasp.org/www-project-secure-headers/

### 6. [Info] Teknoloji ifşası: server
- **Araç:** http_probe
- **Hedef:** https://example.com
- **Açıklama:** Sunucu, saldırgana yardımcı olabilecek sürüm/teknoloji bilgisi sızdırıyor.
- **Kanıt:**

  ```
  server: cloudflare
  ```
- **Çözüm:** server başlığını kaldır veya sürüm bilgisini gizle.

---
_VulnPilot ile üretildi. Yalnızca yetkili test içindir._