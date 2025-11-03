# Nguard - Türkçe Dokumentasyon

Hoşgeldiniz! Bu klasörde Nguard'ın kapsamlı Türkçe dokümantasyonunu bulabilirsiniz.

## 📚 Rehberler

### Başlamak İçin
1. **[Hızlı Başlangıç](./QUICKSTART.md)** - 5 dakikada kurulum
2. **[Temel Kullanım](./GETTING-STARTED.md)** - İlk projenizi kurun

### API Referansı
3. **[Server API](./API-SERVER.md)** - Server tarafı fonksiyonları
4. **[Client API](./API-CLIENT.md)** - Client hooks ve components
5. **[Callbacks](./CALLBACKS.md)** - Callback'ler ve nasıl kullanılacağı

### İleri Konular
6. **[Session Güncelleme](./SESSION-UPDATE.md)** - Mevcut session'ı güncelleme
7. **[Örnekler](./EXAMPLES.md)** - Gerçek dünya örnekleri
8. **[Best Practices](./BEST-PRACTICES.md)** - En iyi uygulamalar
9. **[Middleware](./MIDDLEWARE.md)** - Rota koruması

## 🎯 Hızlı Başlangıç

```bash
# 1. Kur
npm install nguard

# 2. docs/tr/QUICKSTART.md'ı oku
# 3. Callback'leri implement et
# 4. API route'ları oluştur
# 5. SessionProvider'ı setup et
# 6. useAuth() kullan
```

## 📖 Mevcut Dökümentasyon

| Sayfa | Açıklama |
|-------|----------|
| [QUICKSTART.md](./QUICKSTART.md) | 5 dakikalık başlangıç |
| [GETTING-STARTED.md](./GETTING-STARTED.md) | Detaylı ilk kurulum |
| [API-SERVER.md](./API-SERVER.md) | Server fonksiyonları ve callback'ler |
| [API-CLIENT.md](./API-CLIENT.md) | Client hooks ve SessionProvider |
| [CALLBACKS.md](./CALLBACKS.md) | Callback'ler nasıl çalışır |
| [SESSION-UPDATE.md](./SESSION-UPDATE.md) | Session güncelleme rehberi ve örnekler |
| [EXAMPLES.md](./EXAMPLES.md) | Gerçek kullanım örnekleri |
| [BEST-PRACTICES.md](./BEST-PRACTICES.md) | Güvenlik ve best practices |
| [MIDDLEWARE.md](./MIDDLEWARE.md) | Next.js middleware setup |

## 🤔 Neyi Arıyorsunuz?

**Hızlı bir şekilde başlamak istiyorum**
→ [QUICKSTART.md](./QUICKSTART.md)

**Server callback'lerini anlamak istiyorum**
→ [CALLBACKS.md](./CALLBACKS.md) → [API-SERVER.md](./API-SERVER.md)

**Client tarafını kurmak istiyorum**
→ [API-CLIENT.md](./API-CLIENT.md) → [EXAMPLES.md](./EXAMPLES.md)

**Spring backend ile entegrasyon yapacağım**
→ [EXAMPLES.md](./EXAMPLES.md) → [CALLBACKS.md](./CALLBACKS.md)

**Güvenlikle ilgili sorularım var**
→ [BEST-PRACTICES.md](./BEST-PRACTICES.md)

**Korumalı route'lar kurmak istiyorum**
→ [MIDDLEWARE.md](./MIDDLEWARE.md)

**Session'ımı güncellemek istiyorum (rol, tema, vb.)**
→ [SESSION-UPDATE.md](./SESSION-UPDATE.md)

## 💡 Temel Kavramlar

### Callback Sistemi
Nguard'ın kalbi callback'leridir. Siz:
- **Server-side**: Kullanıcı auth, token validation, cleanup
- **Client-side**: Frontend login, logout, init

### Akış
```
User Login Form
    ↓
useAuth().login(credentials)
    ↓
Client onLogin callback
    ↓
POST /api/auth/login
    ↓
Server onServerLogin callback
    ↓
JWT + Cookie
    ↓
useAuth() state update
    ↓
Component re-render ✅
```

## 🚀 İlk Adım

1. Bu rehberi okuyun (5 min)
2. [QUICKSTART.md](./QUICKSTART.md) izleyin (5 min)
3. [CALLBACKS.md](./CALLBACKS.md) okuyun (10 min)
4. [EXAMPLES.md](./EXAMPLES.md) inceleyin (10 min)
5. Kodunuzu yazın!

---

**English?** → See [../../docs/en/](../../docs/en/README.md)
