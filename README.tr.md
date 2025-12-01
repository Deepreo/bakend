# Bakend Framework

`bakend-framework`, Go ile geliştirilmiş, modüler, ölçeklenebilir ve modern backend uygulamaları geliştirmek için tasarlanmış güçlü bir framework'tür. CQRS (Command Query Responsibility Segregation), Event-Driven Architecture ve Clean Architecture prensiplerini benimseyerek, geliştiricilere sağlam bir temel sunar.

## Özellikler

- **Modüler Yapı:** Uygulamanızı bağımsız modüllere ayırarak yönetilebilirliği ve test edilebilirliği artırır.
- **CQRS Desteği:** Komut (Command) ve Sorgu (Query) sorumluluklarını ayırarak performans ve ölçeklenebilirlik sağlar.
- **Event-Driven Mimari:** Modüller arası iletişimi olaylar (events) üzerinden sağlayarak gevşek bağlılık (loose coupling) sunar.
- **Dahili Sunucu:** HTTP sunucusu entegrasyonu ile hızlıca API geliştirmeye başlayabilirsiniz.
- **Zamanlayıcı (Scheduler):** Arka plan görevlerini ve zamanlanmış işleri yönetmek için dahili zamanlayıcı desteği.
- **Genişletilebilir:** Kendi modüllerinizi ve bileşenlerinizi kolayca entegre edebilirsiniz.

## Kurulum

Projenize `bakend-framework`'ü eklemek için aşağıdaki komutu kullanabilirsiniz:

```bash
go get github.com/Deepreo/bakend
```

## Kullanım

Basit bir `bakend` uygulaması oluşturmak için aşağıdaki adımları izleyebilirsiniz:

```go
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/Deepreo/bakend"
	"github.com/Deepreo/bakend/core"
	// ... diğer importlar
)

func main() {
    // Logger oluştur
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

    // Gerekli bileşenleri başlat (Server, Bus'lar, vb.)
    // Not: Bu bileşenlerin implementasyonları framework içinde veya harici olarak sağlanmalıdır.
    // Örnek olarak mock veya in-memory implementasyonlar kullanılabilir.
    
    // Uygulamayı oluştur
    app, err := bakend.New(
        server,
        commandBus,
        queryBus,
        eventBus,
        scheduler,
        *logger,
    )
    if err != nil {
        logger.Error("Uygulama oluşturulamadı", "error", err)
        os.Exit(1)
    }

    // Uygulamayı çalıştır
    if err := app.Run(context.Background()); err != nil {
        logger.Error("Uygulama hatası", "error", err)
        os.Exit(1)
    }
}
```

## Modüller

Framework, çeşitli işlevler için hazır modüller sunar (veya sunmayı hedefler):

- **Auth:** Kimlik doğrulama ve yetkilendirme.
- **Database:** Veritabanı bağlantı ve yönetim işlemleri.
- **Cache:** Önbellekleme mekanizmaları.
- **Event:** Olay yönetimi ve dağıtımı.
- **Scheduler:** Zamanlanmış görevler.

## Lisans

Bu proje [GNU General Public License v3.0](LICENSE) altında lisanslanmıştır. Daha fazla bilgi için `LICENSE` dosyasına bakabilirsiniz.
