import sys
import socket
import paramiko
import subprocess
import re
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QProgressBar, QMessageBox, QGroupBox, QFormLayout)
from PyQt6.QtCore import QRunnable, QThreadPool, pyqtSignal, QObject, Qt

# --- SİNYALLER ---
class WorkerSignals(QObject):
    log = pyqtSignal(str)      
    progress = pyqtSignal()    
    finished = pyqtSignal()
    result_ips = pyqtSignal(list) # Tarama sonucu bulunan IP listesini taşır

# --- SSH İŞÇİSİ (Şifre Değiştirme) ---
class SSHWorker(QRunnable):
    def __init__(self, ip, admin_user, admin_pass, target_user, target_pass):
        super().__init__()
        self.ip = ip
        self.admin_user = admin_user
        self.admin_pass = admin_pass
        self.target_user = target_user
        self.target_pass = target_pass
        self.signals = WorkerSignals()

    def check_port_22(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.ip, 22))
            sock.close()
            return result == 0
        except:
            return False

    def run(self):
        if not self.check_port_22():
            self.signals.log.emit(f"⚠️  {self.ip}: Erişim yok veya kapalı. (Atlandı)")
            self.signals.finished.emit()
            return

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            self.signals.log.emit(f"🔄 {self.ip}: Bağlanılıyor...")
            client.connect(self.ip, username=self.admin_user, password=self.admin_pass, timeout=5)
            
            command = f"echo '{self.admin_pass}' | sudo -S sh -c 'echo \"{self.target_user}:{self.target_pass}\" | chpasswd'"
            
            stdin, stdout, stderr = client.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()

            if exit_status == 0:
                self.signals.log.emit(f"✅ {self.ip}: Şifre başarıyla değiştirildi.")
            else:
                hata = stderr.read().decode().strip()
                self.signals.log.emit(f"❌ {self.ip}: Hata! ({hata})")

        except Exception as e:
            self.signals.log.emit(f"❌ {self.ip}: Bağlantı hatası: {str(e)}")
        
        finally:
            client.close()
            self.signals.progress.emit()
            self.signals.finished.emit()

# --- YENİ: NMAP TARAMA İŞÇİSİ ---
class ScanWorker(QRunnable):
    def __init__(self, network_range):
        super().__init__()
        self.network_range = network_range
        self.signals = WorkerSignals()

    def run(self):
        self.signals.log.emit(f"🔍 Ağ taranıyor: {self.network_range} (Lütfen bekleyin...)")
        found_ips = []
        
        try:
            # nmap komutu: -sn (port tarama yapma, sadece ping), -n (DNS çözme, hız için)
            cmd = ["nmap", "-sn", "-n", self.network_range]
            
            # Subprocess ile komutu çalıştır
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                self.signals.log.emit(f"❌ Tarama Hatası: nmap bulunamadı veya yetki yok.\n{stderr}")
                return

            # Çıktıyı analiz et (Regex ile IP yakala)
            # Çıktı formatı: "Nmap scan report for 10.46.197.2"
            lines = stdout.splitlines()
            for line in lines:
                if "Nmap scan report for" in line:
                    # Satırın sonundaki IP'yi al
                    parts = line.split()
                    ip = parts[-1]
                    # Parantez varsa temizle (bazen (192.168...) şeklinde döner)
                    ip = ip.replace("(", "").replace(")", "")
                    found_ips.append(ip)

            self.signals.result_ips.emit(found_ips)
            self.signals.log.emit(f"✅ Tarama bitti. {len(found_ips)} cihaz bulundu.")

        except FileNotFoundError:
            self.signals.log.emit("❌ Hata: 'nmap' yüklü değil. Lütfen 'sudo apt install nmap' yapın.")
        except Exception as e:
            self.signals.log.emit(f"❌ Beklenmedik hata: {str(e)}")

# --- ANA ARAYÜZ ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pardus ETAP Yönetici Asistanı v2.0")
        self.resize(650, 750)
        self.threadpool = QThreadPool()
        
        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()

        # 1. Admin Bilgileri
        group_admin = QGroupBox("1. Yönetici Bilgileri")
        layout_admin = QFormLayout()
        self.input_admin_user = QLineEdit("etapadmin")
        self.input_admin_pass = QLineEdit()
        self.input_admin_pass.setEchoMode(QLineEdit.EchoMode.Password)
        layout_admin.addRow("Yönetici Kullanıcı:", self.input_admin_user)
        layout_admin.addRow("Yönetici Şifresi:", self.input_admin_pass)
        group_admin.setLayout(layout_admin)
        main_layout.addWidget(group_admin)

        # 2. Hedef Bilgileri
        group_target = QGroupBox("2. Hedef Kullanıcı Bilgileri")
        layout_target = QFormLayout()
        self.input_target_user = QLineEdit("ogretmen")
        self.input_target_pass = QLineEdit()
        self.input_target_pass.setPlaceholderText("Yeni Şifreyi Buraya Yazın")
        layout_target.addRow("Kullanıcı Adı:", self.input_target_user)
        layout_target.addRow("YENİ Şifre:", self.input_target_pass)
        group_target.setLayout(layout_target)
        main_layout.addWidget(group_target)

        # 3. Ağ Tarama ve IP Listesi (GÜNCELLENEN KISIM)
        group_ips = QGroupBox("3. Hedef Tahtalar")
        layout_ips_main = QVBoxLayout()
        
        # Tarama Alanı
        layout_scan = QHBoxLayout()
        self.input_network = QLineEdit("10.46.197.0/24") # Varsayılan ağ
        self.input_network.setPlaceholderText("Örn: 192.168.1.0/24")
        
        self.btn_scan = QPushButton("🔍 Ağı Tara ve Listeyi Doldur")
        self.btn_scan.setStyleSheet("background-color: #3498db; color: white; font-weight: bold;")
        self.btn_scan.clicked.connect(self.start_scan)
        
        layout_scan.addWidget(QLabel("Ağ Aralığı:"))
        layout_scan.addWidget(self.input_network)
        layout_scan.addWidget(self.btn_scan)
        
        layout_ips_main.addLayout(layout_scan)

        # Liste Alanı
        self.text_ips = QTextEdit()
        self.text_ips.setPlaceholderText("IP adresleri buraya gelecek...\nveya elle yazabilirsiniz.")
        layout_ips_main.addWidget(self.text_ips)
        
        group_ips.setLayout(layout_ips_main)
        main_layout.addWidget(group_ips)

        # 4. İşlem Butonu ve İlerleme
        self.btn_start = QPushButton("🚀 Şifre Değiştirme İşlemini Başlat")
        self.btn_start.setStyleSheet("background-color: #2ecc71; color: white; font-weight: bold; padding: 12px; font-size: 14px;")
        self.btn_start.clicked.connect(self.start_change_process)
        main_layout.addWidget(self.btn_start)

        self.progress_bar = QProgressBar()
        main_layout.addWidget(self.progress_bar)

        # 5. Log Ekranı
        self.text_log = QTextEdit()
        self.text_log.setReadOnly(True)
        self.text_log.setStyleSheet("background-color: #2c3e50; color: #ecf0f1; font-family: monospace; font-size: 11px;")
        main_layout.addWidget(self.text_log)

        central_widget.setLayout(main_layout)

    def log_message(self, msg):
        self.text_log.append(msg)
        # Scroll en alta insin
        sb = self.text_log.verticalScrollBar()
        sb.setValue(sb.maximum())

    # --- TARAMA FONKSİYONLARI ---
    def start_scan(self):
        network = self.input_network.text().strip()
        if not network:
            QMessageBox.warning(self, "Hata", "Lütfen bir ağ aralığı girin (Örn: 192.168.1.0/24)")
            return

        self.btn_scan.setEnabled(False) # Butonu kilitle
        self.text_ips.clear()
        
        worker = ScanWorker(network)
        worker.signals.log.connect(self.log_message)
        worker.signals.result_ips.connect(self.handle_scan_result)
        self.threadpool.start(worker)

    def handle_scan_result(self, ip_list):
        self.btn_scan.setEnabled(True) # Butonu aç
        
        if not ip_list:
            QMessageBox.information(self, "Bilgi", "Bu ağ aralığında açık cihaz bulunamadı.")
            return

        # Listeyi ekrana yaz
        ips_text = "\n".join(ip_list)
        self.text_ips.setText(ips_text)
        
        # Dosyaya kaydet
        try:
            with open("tahtalar.txt", "w") as f:
                f.write(ips_text)
            self.log_message(f"💾 Liste 'tahtalar.txt' olarak kaydedildi.")
            QMessageBox.information(self, "Başarılı", f"{len(ip_list)} adet cihaz bulundu ve listeye eklendi.")
        except Exception as e:
            self.log_message(f"❌ Dosya kaydetme hatası: {e}")

    # --- ŞİFRE DEĞİŞTİRME FONKSİYONLARI ---
    def update_progress(self):
        self.progress_bar.setValue(self.progress_bar.value() + 1)

    def start_change_process(self):
        admin_u = self.input_admin_user.text().strip()
        admin_p = self.input_admin_pass.text().strip()
        target_u = self.input_target_user.text().strip()
        target_p = self.input_target_pass.text().strip()
        raw_ips = self.text_ips.toPlainText().strip().split('\n')
        ip_list = [ip.strip() for ip in raw_ips if ip.strip()]

        if not ip_list:
            QMessageBox.warning(self, "Hata", "IP listesi boş.")
            return
        if not admin_p or not target_p:
            QMessageBox.warning(self, "Hata", "Şifre alanları boş olamaz.")
            return

        self.progress_bar.setMaximum(len(ip_list))
        self.progress_bar.setValue(0)
        self.btn_start.setEnabled(False)
        self.active_workers = len(ip_list)
        
        self.log_message(f"🚀 {len(ip_list)} tahta için işlem başlatılıyor...")

        for ip in ip_list:
            worker = SSHWorker(ip, admin_u, admin_p, target_u, target_p)
            worker.signals.log.connect(self.log_message)
            worker.signals.progress.connect(self.update_progress)
            worker.signals.finished.connect(self.check_finished)
            self.threadpool.start(worker)

    def check_finished(self):
        self.active_workers -= 1
        if self.active_workers == 0:
            self.btn_start.setEnabled(True)
            self.log_message("🏁 Tüm işlemler tamamlandı.")
            QMessageBox.information(self, "Bitti", "Tüm işlemler tamamlandı.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
