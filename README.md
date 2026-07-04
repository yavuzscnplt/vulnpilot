# 🛡️ VulnPilot

**AI-orchestrated web application security scanner.**

VulnPilot uses a Claude-powered "brain" to plan a security scan, drive mature
open-source tooling (nuclei, subfinder) plus built-in probes, and then triage
the results into a human-readable report — JSON, Markdown and a self-contained
HTML page.

It is a **security orchestrator**, not yet another scanner: instead of
reinventing detection engines, it makes the good ones work together and adds
the judgement layer on top.

[![CI](https://github.com/yavuzscnplt/vulnpilot/actions/workflows/ci.yml/badge.svg)](https://github.com/yavuzscnplt/vulnpilot/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-alpha-orange)

---

## ⚠️ Yasal Uyarı / Legal

VulnPilot **yalnızca yetkili güvenlik testleri** içindir. Yalnızca sahibi
olduğun ya da yazılı olarak test etme izni aldığın sistemlere karşı çalıştır.
İzinsiz tarama birçok ülkede suçtur. Sorumluluk kullanıcıya aittir.

VulnPilot is for **authorized security testing only.** Only run it against
systems you own or have explicit written permission to test.

---

## Nasıl çalışır?

```
   ┌──────────┐     ┌───────────────┐     ┌──────────────┐
   │  Hedef   │ ──▶ │  🧠 AI PLAN   │ ──▶ │  ▶ EXECUTE   │
   └──────────┘     │ araç seçimi    │     │ araçları koş │
                    └───────────────┘     └──────┬───────┘
                                                 │
                    ┌───────────────┐            ▼
   📄 Rapor  ◀────── │ 📝 AI TRİAJ   │ ◀── bulguları topla
   JSON/MD/HTML     │ özet + öncelik │
                    └───────────────┘
```

1. **Plan** — Claude, hedefi ve o makinede kullanılabilir araçları görür, güvenli
   bir tarama planı seçer (yıkıcı/DoS eylem önermez).
2. **Execute** — Seçilen araçlar sırayla koşar. Harici araç yoksa dahili
   Python probe'ları yine gerçek bulgu üretir.
3. **Interpret** — Claude ham bulguları yönetici özeti + önceliklendirilmiş
   düzeltme listesine çevirir.

> **AI olmadan da çalışır.** `ANTHROPIC_API_KEY` yoksa VulnPilot deterministik
> heuristik moda düşer: tüm güvenli araçları koşar ve kural tabanlı özet üretir.
> Böylece repoyu klonlayan herkes anahtar olmadan da uçtan uca deneyebilir.

---

## Araçlar

| Araç | Tür | Ne yapar | Gereksinim |
|------|-----|----------|------------|
| `http_probe` | dahili | Güvenlik başlıkları, çerez bayrakları, teknoloji ifşası | — (her zaman çalışır) |
| `tls_probe`  | dahili | TLS sürümü + sertifika geçerliliği/son kullanma | — (her zaman çalışır) |
| `nuclei`     | harici | Bilinen zafiyet/CVE ve yanlış yapılandırma taraması | [`nuclei`](https://github.com/projectdiscovery/nuclei) |
| `subfinder`  | harici | Pasif alt alan adı keşfi | [`subfinder`](https://github.com/projectdiscovery/subfinder) |

Yeni araç eklemek bir dosya: `Tool` sınıfından türet, `@register` ile işaretle.

---

## Kurulum

```bash
git clone https://github.com/yavuzscnplt/vulnpilot.git
cd vulnpilot
pip install -e .

# AI beyni için (opsiyonel):
pip install -e ".[ai]"
cp .env.example .env    # ve ANTHROPIC_API_KEY doldur
```

Harici araçlar (opsiyonel, daha derin tarama için):

```bash
# ProjectDiscovery araçları — Go gerekir
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

---

## Kullanım

```bash
# Kayıtlı araçları ve durumlarını gör
vulnpilot tools

# Bir hedefi tara (yetki onayı ister)
vulnpilot scan https://ornek.com

# Kendi lokal uygulamanı test et, onayı atla, raporu aç
vulnpilot scan http://localhost:8080 --yes --open

# Rapor klasörünü değiştir
vulnpilot scan https://ornek.com -o ./ciktilar
```

Çıktı: `reports/<host>_<zaman>.{json,md,html}`

### Örnek terminal çıktısı

```
╭───────────────────────────╮
│ VulnPilot v0.1            │
│ AI-orkestralı güvenlik... │
╰───────────────────────────╯

Hedef: http://localhost:8080  (lokal/özel)
Kullanılabilir araçlar: http_probe, tls_probe
AI beyni: açık

  🧠 AI araç planı çıkarıyor
  📋 http_probe, tls_probe
  ▶ http_probe
  ✓ http_probe: 4 bulgu
  ▶ tls_probe
  ✓ tls_probe: 1 bulgu
  📝 AI özet/triaj yazıyor
```

---

## Mimari

```
vulnpilot/
├── cli.py           # Typer + Rich terminal arayüzü
├── config.py        # ortam değişkeni tabanlı ayarlar
├── scope.py         # yetki/kapsam koruması (etik omurga)
├── llm.py           # Claude sarmalayıcı + AI-kapalı fallback
├── orchestrator.py  # plan → execute → interpret döngüsü
├── models.py        # tipli veri modelleri (Finding, ScanReport…)
├── report.py        # JSON / Markdown / HTML üretimi
└── tools/           # eklenti araçlar (@register ile kaydolur)
    ├── base.py      # Tool ABC + registry
    ├── http_probe.py
    ├── tls_probe.py
    ├── nuclei.py
    └── subfinder.py
```

Tasarım ilkeleri: eklenti mimarisi (yeni araç = bir dosya), zarif bozulma
(araç/AI yoksa da çalışır), tek dosyalık paylaşılabilir HTML rapor, ve
**önce yetki** — hiçbir trafik onaysız gönderilmez.

---

## Geliştirme

```bash
pip install -e ".[dev]"
pytest            # testler (ağ/harici araç gerektirmez)
ruff check .      # lint
```

---

## Yol Haritası

- [ ] Aktif tarama için OWASP ZAP entegrasyonu
- [ ] API (REST/GraphQL) endpoint keşfi ve fuzzing
- [ ] Paralel araç çalıştırma
- [ ] Otonom ajan modu (AI'nın kendi payload denediği)
- [ ] SARIF çıktısı (CI/CD entegrasyonu)

---

## Lisans

MIT — bkz. [LICENSE](LICENSE).
