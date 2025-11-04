# Nguard - Next.js 16+ Oturum Yönetimi Kütüphanesi

## 🚀 Yeni Sürüm: Nguard v0.3.4

**Nguard**'ın en yeni sürümünü duyurmaktan heyecan duyuyorum! Next.js 16+ için güçlü ve basit bir oturum yönetimi kütüphanesi.

### Nguard Nedir?

Nguard, **sıfır konfigürasyon kimlik doğrulama çözümü** olup, oturum yönetimini çok kolaylaştırır:

✅ **JWT Tabanlı Oturumlar** - Güvenli, durumsuz kimlik doğrulama
✅ **Sıfır Konfigürasyon** - `npx nguard-setup` ile hemen başla
✅ **TypeScript Odaklı** - %100 tip güvenliği
✅ **Herhangi Bir Backend ile Çalışır** - Spring, Express, Django, Python veya herhangi bir REST API
✅ **Sunucu & İstemci Hook'ları** - Hem server component'ler hem de client-side hook'lar
✅ **Yerleşik Ara Yazılımlar** - Rol tabanlı erişim kontrol, hız sınırlandırma, CORS
✅ **Oturum Doğrulama** - İstediğin zaman oturumu doğrula ve yenile

### v0.3.4 ile Gelen Yenilikler

**Sunucu Tarafı Oturum Yönetimi:**
```typescript
import { nguard } from '@/lib/auth';

// Oturum oluştur
const { session, setCookieHeader } = await nguard.createSession({
  id: 'user-123',
  email: 'user@example.com',
  role: 'admin',
  expires: Date.now() + 24 * 60 * 60 * 1000,
});

// Temizleme ile çıkış yap
const cookieHeader = await nguard.logout(session);
```

**İstemci Tarafı Hook'ları:**
```typescript
const { session, loading } = useSession();
const { login, isLoading } = useLogin();
const { logout, isLoading } = useLogout();
const { validate, isValid } = useValidateSession();
```

**Server Component'ler:**
```typescript
import { auth } from '@/lib/auth';

export default async function Dashboard() {
  const session = await auth();
  return <div>Hoşgeldin, {session?.email}</div>;
}
```

### Nasıl Çalışır?

1. **Kur**: `npm install nguard`
2. **Ayarla**: `npx nguard-setup` - İnteraktif sihirbaz
3. **Kullan**: Hook'lar ve sunucu fonksiyonları ile geliştir

Sihirbaz otomatik olarak şunları oluşturur:
- `lib/auth.ts` - Sunucu yardımcı işlevleri
- Giriş, çıkış, doğrulama, yenileme API route'ları
- `proxy.ts` - Next.js 16 ara yazılımı yapılandırması
- Ortam değişkenleri şablonu

### Neden Nguard?

- **Vendor bağımlılığı yok** - Mevcut backend'inizle çalışır
- **Esnek oturum yapısı** - İhtiyacınız olan herhangi bir veriyi saklayın
- **Üretime hazır** - HTTP-only cookie'ler, CSRF koruması, JWT doğrulaması
- **Geliştirici dostu** - TypeScript ve hook'lar ile harika geliştirici deneyimi
- **Birleştirilebilir ara yazılımlar** - Karmaşık kimlik doğrulama akışları kolaylıkla oluştur

### Dokümantasyon

Tam dokümantasyon İngilizce ve Türkçe olarak mevcut:
- 📖 CLI Kurulum Rehberi
- 🚀 Hızlı Başlangıç
- 📚 API Referansı
- ⚙️ Ara Yazılım Rehberi
- ✔️ Oturum Doğrulama Rehberi

### Hızlı Başlangıç

```bash
npm install nguard
npx nguard-setup
```

Sonra uygulamayı sar:
```typescript
import { SessionProvider } from 'nguard/client';

export default function RootLayout({ children }) {
  return (
    <SessionProvider>
      {children}
    </SessionProvider>
  );
}
```

### GitHub

Açık kaynak ve ücretsiz kullanım. Kontrol et:
https://github.com/trxyazilimedu/nguard

### npm

npm kayıt defterinde mevcut:
https://www.npmjs.com/package/nguard

---

**Geri bildirim veya önerilerin var mı?** GitHub'da issue aç veya benimle iletişime geç!

Harika kimlik doğrulama çözümleri geliştirmek için heyecan duyuyorum! 🔐

#NextJS #KimlikDoğrulama #JWT #TypeScript #AçıkKaynak #WebGeliştirme #React #Türkçe
