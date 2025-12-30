## Pardus ETAP Yöneticileri İçin Ağ Üzerinden Toplu Şifre Değiştirme Python Uygulaması
İşte "Pardus Toplu Şifre Değiştirici" uygulamanızın kaynak kodları ve çalışma mantığı.

Bu özellik uygulamayı tam bir "İsviçre Çakısı"na dönüştürür. IP adreslerini tek tek elle girmek yerine, tek tuşla ağdaki aktif tahtaları bulmak kullanıcı deneyimini zirveye taşır.

Bunun için uygulamamıza şu özellikleri ekleyeceğiz:

Nmap Entegrasyonu: Arka planda nmap komutunu çalıştıracak bir yapı.

IP Aralığı Kutusu: Hangi ağı tarayacağını belirtmek için (Örn: 10.46.197.0/24).

Otomatik Kayıt: Bulunan IP'leri hem ekrana yazacak hem de tahtalar.txt dosyasına kaydedecek.
### Nasıl Çalıştırılır?
Dosyayı kaydettiğiniz klasörde terminali açın.

##### sudo python3 pardus_yonetici.py
komutunu yazın.

Karşınıza gelen ekranda:

Yönetici Bilgileri: Tahtalara bağlanırken kullandığınız admin hesabını (örn: etapadmin) ve şifresini girin.

Hedef Bilgileri: Şifresini değiştirmek istediğiniz kullanıcıyı (örn: ogretmen) ve yeni şifreyi yazın.

IP Listesi: tahtalar.txt dosyanızdaki veya nmap çıktısındaki IP adreslerini kopyalayıp buraya yapıştırın.

İşlemi Başlat butonuna basın.

<img width="525" height="639" alt="image" src="https://github.com/user-attachments/assets/a5d27805-cc6e-41b8-a186-2a9f10141071" />

<img width="525" height="639" alt="image" src="https://github.com/user-attachments/assets/4774a260-e8b9-445c-81cc-11f19e6d27c4" />

