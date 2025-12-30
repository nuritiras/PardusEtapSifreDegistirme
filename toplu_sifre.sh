#!/bin/bash

# --- AYARLAR (Buraları Kendi Sisteminize Göre Düzenleyin) ---
ADMIN_USER="etapadmin"           # Tahtaya bağlanacak yetkili kullanıcı adı
MEVCUT_SSH_SIFRESI="14531453" # Tahtanın şu anki admin şifresi
HEDEF_KULLANICI="ogretmen"       # Şifresi değişecek kullanıcı (ogretmen, ogrenci vb.)
YENI_SIFRE="Muallim.46"   # Yeni belirlediğiniz şifre
# -----------------------------------------------------------

# Dosya kontrolü
if [ ! -f tahtalar.txt ]; then
    echo "Hata: tahtalar.txt dosyası bulunamadı!"
    exit 1
fi

echo "### Toplu Şifre Değiştirme İşlemi Başlıyor ###"
echo "----------------------------------------------"

while IFS= read -r IP; do
    # Boş satırları atla
    [[ -z "$IP" ]] && continue
    
    # ADIM A: SSH Port Kontrolü (Netcat)
    # -z: Sadece portu yokla (veri gönderme)
    # -w 2: 2 saniye bekle, cevap yoksa zaman aşımına uğra
    nc -z -w 2 "$IP" 22
    
    if [ $? -ne 0 ]; then
        echo "⚠️  $IP: Erişim yok veya SSH kapalı. (Hızla atlanıyor...)"
        echo "----------------------------------------------"
        continue
    fi

    # ADIM B: SSH ile bağlan ve şifreyi değiştir
    echo "🔄 $IP: Tahta açık, bağlantı kuruluyor..."
    
    # sshpass: Şifreyi otomatik girer
    # StrictHostKeyChecking=no: "Emin misiniz" sorusunu atlar
    # chpasswd: Şifreyi interaktif olmayan modda değiştirir
    
    sshpass -p "$MEVCUT_SSH_SIFRESI" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 $ADMIN_USER@$IP \
    "echo '$MEVCUT_SSH_SIFRESI' | sudo -S sh -c 'echo \"$HEDEF_KULLANICI:$YENI_SIFRE\" | chpasswd'"

    if [ $? -eq 0 ]; then
        echo "✅ $IP: Şifre BAŞARIYLA değiştirildi."
    else
        echo "❌ $IP: Bağlantı hatası veya şifre yanlış."
    fi
    echo "----------------------------------------------"

done < tahtalar.txt

echo "Tüm işlemler tamamlandı."
