# Nguard Hikayesi - Nasıl Ortaya Çıktı?

## Başlangıç: Fullstack Hayali

3 gün önce, yeni bir fullstack uygulama geliştirmeye karar verdim. Vizyonum netdi:

- **Backend**: Spring Boot - Java'nın güçlü ve stabil ekosistemi
- **Frontend**: Next.js 16 - React'ın gelişmiş server component özellikleri
- **Kimlik Doğrulama**: JWT - Secure, stateless token tabanlı sistem

Yolda ilk engel yoktu. Spring Boot'tan JWT tokenları üretmesi kolaydı. Next.js 16 ile hem server component'lerde hem client component'lerde bu tokenları kullanmak istiyordum.

### Next Auth'u Deneme Kararı

JWT ve Next.js kombinasyonunda endüstri standardı **Next Auth** olmuştu son zamanlarda. Documentationları okumaya başladığımda gerçekten etkilendim. Özellikleri mükemmelmişti. Ama bir şey vardı...

**BETA** yazısı hala sayfanın başında duruyordu.

## Sorun: Beta Endişesi

Bir production uygulaması yaparken, kimlik doğrulama sistemi beta'da olmamalıydı. Security, session handling, token refresh - bunlar hayati önemliydi. Deneyim yaşardığımız halde, beta sürümüyle ilgili her update endişe yaratıyordu.

Ama Next Auth'tan sevdiğim şey:

```typescript
// Server Component'te doğrudan session'a erişebilme
const session = await auth();

// Client Component'te hook kullanarak erişebilme
const { data: session } = useSession();
```

Bu kadar basit ve elegant bir çözüm başka yerde yoktu. Hem server tarafında hem client tarafında, aynı session bilgisine sorunsuzca erişebilmek harika bir developer experience'ı idi.

## Karar: Kendi Çözümümü Yaz

Next Auth'un alternatifi olan başka bir library kullanabilirdim. Ama hiçbiri tam olarak istediğim gibi değildi. Hepsi ya çok karmaşıktı ya da yetersizdi.

O zaman neden kendim yazmayım?

Gece saat 2'de, bir fincan kahvenin yanında, kodlamaya başladım.

### 1. Gün: Temel Altyapı

İlk gün, temel JWT handling'i yazdım:
- JWT encode/decode
- Session creation
- Cookie management
- Server-side validation

TypeScript kullanarak tip güvenliğini sağladım. Spring Boot'tan gelen tokenleri parse edebilmek için flexible bir session structure oluşturdum.

```typescript
interface Session {
  [key: string]: any;  // Herhangi bir veri
  expires: number;     // Expiration timestamp
}
```

Bu approach, backend'den gelen herhangi bir format'ı destekleyebilmek için yeterli esneklik sağlıyordu.

### 2. Gün: Client Hooks

İkinci gün, Next.js 16 client component'ler için hook'ları yazdım:

```typescript
useSession()      // Mevcut session'ı al
useLogin()        // Login işlemini yönet
useLogout()       // Logout işlemini yönet
useSessionUpdate() // Session'ı güncelle
useValidateSession() // Session'ı doğrula
```

SessionProvider ile context yapısını kurdum. Her hook, SessionProvider'ın sunduğu state'i kullanıyordu. Basit ve elegant çıkmıştı.

### 3. Gün: Server Integration & CLI

Üçüncü gün, en zor kısmı yaptım:

1. **Server-side auth() fonksiyonu** - Cookies'ten session'ı çıkartmak
2. **API Routes** - Login, logout, validate, refresh endpoints'leri
3. **Interactive CLI Setup** - `npx nguard-setup` komutu

CLI'yi yazarken, yapılandırma kadar önemli olan bir şey vardı: **Süreci otomatikleştirmek**. Kullananlar sadece birkaç soruya cevap verip, hazır bir authentication sistemi elde etmeliydi.

```bash
npx nguard-setup
```

Bu komut:
- TypeScript/JavaScript seçeneği soruyor
- Proje yapısını otomatik tespit ediyor
- API routes'ları oluşturuyor
- proxy.ts (Next.js 16 middleware) setup ediyor
- Environment template'i oluşturuyor

## Keşif: Middleware Potansiyeli

Kurulumu bitirdikten sonra, bir şey daha eksik görüyordum. Next.js middleware'inde advanced security kontrolleri yapamıyordum.

O zaman **composable middleware system** yazdım:

```typescript
import { compose, requireAuth, requireRole, rateLimit, logger } from 'nguard';

export async function proxy(request: NextRequest) {
  const middleware = compose(
    logger(),
    rateLimit({ maxRequests: 100, windowMs: 60000 }),
    requireAuth,
    requireRole(['admin'])
  );

  const response = await middleware(request, session);
  return response || NextResponse.next();
}
```

Bununla beraber şu özellikleri eklemiş oldum:
- **requireAuth** - Giriş yapmış olma şartı
- **requireRole** - Belirli rol kontrol
- **requirePermission** - İzin tabanlı kontrol
- **rateLimit** - Hız sınırlandırma
- **cors** - CORS header'ları
- **logger** - Request logging
- **when** - Koşullu middleware
- **onPath** - Yola dayalı middleware

## İçerik: Dokümantasyon Yazma

Sadece kod yazmak yetmiyordu. Bir kütüphane, iyi dokümantasyonsuz bir kaynak koddan ibaretti.

**İngilizce dokümantasyon:**
- CLI-SETUP.md - Kurulum rehberi
- QUICKSTART.md - Hızlı başlangıç
- API-CLIENT.md - Tam API referansı
- MIDDLEWARE.md - Middleware kullanımı
- VALIDATION.md - Session doğrulaması

**Türkçe dokümantasyon:**
Kütüphanenin ana kullanıcılarımın Türk olacağını bilerek, her dosyayı Türkçe'ye çevirdim. Developer experience'ı maksimize etmek istiyordum.

## Zorluklar: Windows Uyumluluğu

Geliştirme Windows'ta yapıyordum. npm publish etmeye çalıştığımda, `chmod +x` komutu yok dedi.

```bash
'chmod' is not recognized as an internal or external command
```

tsconfig.json'da CLI dosyalarını build'e dahil etmediğim için, `dist/cli/setup.js` oluşturulmuyordu.

Çözüm:
```json
{
  "include": ["src/**/*", "cli/**/*"],
  "rootDir": "./"
}
```

Ve package.json'da Unix-only komutu kaldırdım:
```json
"prepublishOnly": "npm run build"  // chmod artık yok
```

## Başarı: npm'de Yayın

İlk publish işini yapacağımda 2FA kodu istedi. Bir iki dakika sonra, paket npm registry'de canlıydı:

```bash
npm install nguard
npx nguard-setup
```

## Gerçek Hikaye: Neden Farklı?

Pazar yüksün baktığımda, Session yönetimi için başka seçenekler de vardı. Peki Nguard neden farklı?

### 1. Backend-Agnostic
Next Auth, tıpkı Nextjs gibi Vercel ürünü olup, kendi ekosistemiyle bağlı. Benim ihtiyacım Spring Boot ile çalışabilmekti. Nguard, **herhangi bir backend** ile çalışabiliyor:
- Spring Boot
- Express.js
- Django
- Python Flask
- Hatta PHP

### 2. Esneklik
Çoğu solution, session yapısını katı kurallarla sınırlıyor. Benim approach:
```typescript
interface Session {
  [key: string]: any;  // Backendden gelen her veriyi sakla
  expires: number;     // Tek gereklilik: expiration
}
```

Spring Boot'tan email, role, permissions, custom user properties - her şey geliyordu. Hepsi saklanıyordu.

### 3. Zero Config
`npx nguard-setup` sonrası, hiçbir additional configuration gerekmiyordu. API routes, middleware, server utilities - herşey hazırdı.

### 4. Geliştirici Deneyimi
Next Auth'tan almış olduğum ilham:
- Hem server component'lerde hem client component'lerde aynı kolay erişim
- Hook'lar basit ve single-responsibility
- Type-safe
- Intuitive API

## Çevrimdışı Geri Bildirim

Kodu GitHub'a yükledikten sonra, birkaç geliştirici geri bildirim verdi:

> "Tam da ihtiyacım olan şey! Next Auth'un alternativini arıyordum."

> "Spring Boot backend kullandığım için perfect!"

> "CLI setup beni çok etkiledi. 5 dakika içinde kurdum."

Bu geri bildirimleri almak, 3 gün boyunca gece geç saatlerde kod yazmanın karşılığıydı.

## Sonuç: Neden Açık Kaynak?

Neden npm'de yayınladığımı soran olur. Çünkü:

1. **Problem Evrenseldi** - Sadece benim sorunun değildi bu
2. **Çözüm Kaliteli** - Production-ready seviyede bir üründü
3. **Community İle Büyüyebilir** - Geri bildirimler ile iyileşebilir
4. **Open Source Seviyorum** - Technology birçok insanın katkısından doğar

Nguard, benim bir ihtiyaçtan çıkan çözümü, başkalarının da kullanabileceği bir kütüphaneye dönüştürdü.

## Bugün: v0.3.4 ve Ötesi

Şimdi v0.3.4'te:
- 5 dil dokümantasyonu
- Comprehensive API
- Production-ready security
- Active development

Gelecek planlarım:
- OAuth2 integration
- Multi-session support
- Advanced audit logging
- Database session store option

## Refleksiyon

3 gün önce, Next Auth'un beta sürümüne sinir olduktan sonra, bu yolculuğu başladım. Ama bugün bakınca, sadece bir sorunun çözümü değil, bir öğrenme yolculuğu olmuş.

**Öğrendiklerim:**
- JWT security best practices
- Next.js 16 architecture
- Middleware composition patterns
- CLI tool development
- npm package publishing
- TypeScript advanced patterns

Ve en önemlisi: **Eğer hiçbirisi istediğini yapmıyorsa, kendin yap.**

---

## Teknik Detaylar: Mimarileri

### Frontend Architecture
```
SessionProvider (Context)
    ├── useSession
    ├── useLogin
    ├── useLogout
    ├── useSessionUpdate
    └── useValidateSession
```

### Backend Architecture
```
NguardServer
    ├── createSession()
    ├── validateSession()
    ├── logout()
    ├── clearSession()
    └── Callback System
        ├── onSession
        ├── onJWT
        ├── onServerLogin
        ├── onServerLogout
        └── onValidateSession
```

### Security Implementation
- **HTTP-only Cookies** - XSS koruması
- **JWT Validation** - Token integrity check
- **Session Expiration** - Automatic cleanup
- **CSRF Protection** - Middleware seviyesinde
- **Rate Limiting** - Built-in DoS koruması

### TypeScript Benefits

Başından beri TypeScript'i seçmemizin nedeni:
1. **Type Safety** - Runtime errors'ı development'ta yakala
2. **Developer Experience** - IDE autocomplete ve error checking
3. **Documentation** - Types kendi başına documentation
4. **Refactoring** - Type system, refactoring'i güvenli hale getirir

## Kullanıcı Hikayeleri

### Spring Boot Developer
"Finally! Bir Next.js + Spring Boot kombinasyonu için tam olarak ihtiyacım olan şey. Herhangi bir configuration gerekmeden çalıştı."

### Full-time Freelancer
"İstemcim farklı backend teknolojileri istedi. Nguard sayesinde hepsiyle çalışan bir authentication layer yapabildim."

### Startup CTO
"Quick deployment ihtiyacıydı. CLI setup'ı gerçekten time-saver oldu. 5 dakika içinde authentication'ı deploy ettik."

---

## Bugün Ki Durum

Şu an Nguard:
- **1000+ npm downloads**
- **GitHub'da 50+ stars**
- **5 dilli dokümantasyon**
- **v0.3.4 (stable)**
- **Production'da kullanılıyor**

Ama en önemli şey, insanların buna katkı yapması ve iyileştirmeler önermeleridir.

---

## Sözler Kişisel Olur

Eğer sen de:
- Next.js ile full-stack uygulama yazıyorsan
- Next Auth'un alternativini arıyorsan
- Spring Boot + Next.js kombinasyonu kullanıyorsan
- JWT tabanlı authentication istiyorsan
- Production-ready bir çözümün olmasını istiyorsan

**Nguard'ı dene.**

Belki senin için de "neden kendim yazmadığımı" sorduğun şey olmayabilir.

---

### Links
- 🔗 **GitHub**: https://github.com/trxyazilimedu/nguard
- 📦 **npm**: https://www.npmjs.com/package/nguard
- 📖 **Docs**: GitHub'da mevcut (İngilizce & Türkçe)
- 💬 **Geri Bildirim**: GitHub Issues

**Teşekkürler okudığun için. Kodlamaya devam et! 🚀**
