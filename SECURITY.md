# Güvenlik Politikası / Security Policy

## Sorumlu Kullanım / Responsible Use

VulnPilot **yalnızca yetkili güvenlik testleri** için bir araçtır. Yalnızca
sahibi olduğun veya test etmek için **açık, yazılı izin** aldığın sistemlere
karşı çalıştır. İzinsiz tarama birçok ülkede suçtur ve tüm sorumluluk
kullanıcıya aittir. Araç, hedefe trafik göndermeden önce yetki onayı ister
(`scope.py`).

VulnPilot is intended for **authorized security testing only.** Run it solely
against systems you own or have explicit written permission to test.

## Zafiyet Bildirimi / Reporting a Vulnerability

VulnPilot'un kendisinde bir güvenlik açığı bulursan, lütfen **herkese açık bir
issue açmadan** özel olarak bildir:

- GitHub'da bir **Security Advisory** aç: `Security → Report a vulnerability`
- veya profildeki iletişim üzerinden ulaş.

Şunları eklersen değerlendirmeyi hızlandırır:
- etkilenen sürüm / commit,
- sorunu yeniden üretme adımları,
- olası etki ve (varsa) öneri.

Makul bir sürede yanıt vermeye ve doğrulanan sorunları düzeltmeye çalışırız.

## Desteklenen Sürümler / Supported Versions

Proje alfa aşamasında (`0.x`). Güvenlik düzeltmeleri yalnızca `main`/`master`
üzerinde en güncel sürüme uygulanır.
