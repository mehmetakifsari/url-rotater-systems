# -*- coding: utf-8 -*-
import os

# --- Qt yazılımsal render (RDP/GPU'suz ortamlar için tavsiye) ---
os.environ["QT_OPENGL"] = "software"
os.environ["QT_QUICK_BACKEND"] = "software"

import sys
import threading
import time
import json
import smtplib
import ssl
import tempfile
import subprocess
from email.mime.text import MIMEText
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode

# WebDriver Manager önbellek/çevrimdışı ayarı
os.environ.setdefault("WDM_LOCAL", "1")
os.environ.setdefault("WDM_OFFLINE", "1")

from PySide6.QtCore import Qt, Signal, QObject, QTime
from PySide6.QtGui import QIcon, QAction
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QListWidget,
    QPushButton, QMenuBar, QMessageBox, QLabel, QDialog, QDialogButtonBox,
    QComboBox, QCheckBox, QFormLayout, QToolBar, QLineEdit, QFileDialog, QSpinBox,
    QListWidgetItem, QTimeEdit, QTextEdit, QSystemTrayIcon, QMenu, QProgressBar,
    QCompleter
)

# Selenium & drivers
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager

# Proxy ön-kontrol ve uzaktan fetch
import requests

APP_DIR = os.path.dirname(__file__)
APP_NAME = "URL Rotator"
APP_ICON = os.path.join(APP_DIR, "img", "favicon.png")

CONFIG_FILE   = os.path.join(APP_DIR, 'config.json')
GROUP_FILE    = os.path.join(APP_DIR, 'group.json')
PROXY_FILE    = os.path.join(APP_DIR, 'proxy.json')
SMTP_FILE     = os.path.join(APP_DIR, 'smtp.json')
URLLIST_FILE  = os.path.join(APP_DIR, 'urllist.json')
LOG_DIR = os.path.join(APP_DIR, 'logs'); os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, 'app.log')

class VPNProvider:
    NONE = "Yok"
    WINDOWS_RAS = "Windows VPN (RAS)"
    WIREGUARD = "WireGuard"
    OPENVPN = "OpenVPN"
    NORDVPN = "NordVPN"

@dataclass
class Settings:
    minutes: int = 1
    use_chrome: bool = True
    use_firefox: bool = False
    use_edge: bool = False
    use_brave: bool = False
    use_opera: bool = False
    chrome_binary: str = ""
    firefox_binary: str = ""
    edge_binary: str = ""
    brave_binary: str = ""
    opera_binary: str = ""
    # UA
    ua_mode: str = "Auto"          # "Auto" | "Manual"
    user_agent: str = ""           # Manuel girilirse kullanılır (opsiyonel)
    # Proxy (tek satır)
    http_proxy: str = ""           # tek-satır acil kullanım
    proxy_enabled: bool = False    # listeyi aktif et
    proxy_failover_secs: int = 120 # 2 dk cevap yoksa sıradaki
    # VPN (genel)
    vpn_provider: str = VPNProvider.NONE
    vpn_exe_path: str = ""
    minimize_to_tray: bool = True
    window_layout: str = "Auto"    # Auto | 2x2 | 1x2 | 1x1

    # --- Yeni: Proxy kaynak/Tip seçimi ---
    proxy_source_mode: str = "Manual"   # Manual | Optional | GH1 | GH2 | GH3
    proxy_type: str = "HTTP"            # HTTP | SOCKS4 | SOCKS5
    proxy_optional_url: str = ""

    # --- YENİ: OpenVPN rotasyonu ayarları ---
    vpn_rotate_enabled: bool = True
    openvpn_exe: str = r"C:\Program Files\OpenVPN\bin\openvpn.exe"
    vpn_ovpn_dir: str = r"C:\Users\Administrator\Desktop\bot\vpn"
    vpn_username: str = "vpnbook"
    vpn_password: str = "m34wk9w"
    vpn_connect_timeout_sec: int = 60
    vpn_stop_timeout_sec: int = 10

@dataclass
class SmtpConfig:
    enabled: bool = False
    host: str = "smtp.gmail.com"
    port: int = 587
    user: str = ""
    password: str = ""
    to_addr: str = ""
    use_tls: bool = True
    use_ssl: bool = False

@dataclass
class ScheduleItem:
    time_hhmm: str
    group_name: str
    vpn_exe_path: str = ""
    enabled: bool = True
    weekdays: List[int] = None  # 0=Mon .. 6=Sun; None/[] -> her gün
    # Bu iş için tarayıcılar (globali override eder)
    use_chrome: Optional[bool] = None
    use_firefox: Optional[bool] = None
    use_edge: Optional[bool] = None
    use_brave: Optional[bool] = None
    use_opera: Optional[bool] = None

# ---------- Yardımcılar ----------
def guess_vpn_exe(provider: str) -> str:
    candidates = []
    if provider == VPNProvider.NORDVPN:
        candidates = [r"C:\Program Files\NordVPN\NordVPN.exe", r"C:\Program Files (x86)\NordVPN\NordVPN.exe"]
    elif provider == VPNProvider.WIREGUARD:
        candidates = [r"C:\Program Files\WireGuard\wireguard.exe"]
    elif provider == VPNProvider.OPENVPN:
        candidates = [r"C:\Program Files\OpenVPN\bin\openvpn-gui.exe", r"C:\Program Files\OpenVPN\bin\openvpn.exe"]
    elif provider == VPNProvider.WINDOWS_RAS:
        candidates = [r"C:\Windows\System32\rasphone.exe", r"C:\Windows\System32\rasdial.exe"]
    for p in candidates:
        if os.path.exists(p): return p
    return ""

def guess_chrome_binary() -> str:
    for p in [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]:
        if os.path.exists(p): return p
    return ""

def guess_firefox_binary() -> str:
    for p in [
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
        r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
    ]:
        if os.path.exists(p): return p
    return ""

def guess_edge_binary() -> str:
    for p in [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]:
        if os.path.exists(p): return p
    return ""

def guess_brave_binary() -> str:
    for p in [
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
    ]:
        if os.path.exists(p): return p
    return ""

def guess_opera_binary() -> str:
    for p in [
        r"C:\Program Files\Opera\opera.exe",
        r"C:\Program Files\Opera GX\opera.exe",
        fr"C:\Users\{os.getenv('USERNAME','')}\AppData\Local\Programs\Opera\opera.exe",
        fr"C:\Users\{os.getenv('USERNAME','')}\AppData\Local\Programs\Opera GX\opera.exe",
    ]:
        if os.path.exists(p): return p
    return ""

DEFAULT_GROUPS = ["Gündüz", "Gece"]

def load_groups() -> List[str]:
    try:
        with open(GROUP_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            gs = [str(x) for x in data]
        else:
            gs = []
    except Exception:
        gs = []
    for g in DEFAULT_GROUPS[::-1]:
        if g in gs: gs.remove(g)
        gs.insert(0, g)
    return gs

def save_groups(groups: List[str]):
    uniq = []
    for g in groups:
        if g not in uniq:
            uniq.append(g)
    try:
        with open(GROUP_FILE, "w", encoding="utf-8") as f:
            json.dump(uniq, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def load_smtp() -> SmtpConfig:
    try:
        with open(SMTP_FILE, "r", encoding="utf-8") as f:
            obj = json.load(f)
        return SmtpConfig(**obj)
    except Exception:
        return SmtpConfig()

def save_smtp(cfg: SmtpConfig):
    try:
        with open(SMTP_FILE, "w", encoding="utf-8") as f:
            json.dump(asdict(cfg), f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def load_proxies() -> List[str]:
    try:
        with open(PROXY_FILE, "r", encoding="utf-8") as f:
            arr = json.load(f)
            if isinstance(arr, list):
                return [str(x).strip() for x in arr if str(x).strip()]
    except Exception:
        pass
    return []

def save_proxies(items: List[str]):
    uniq = []
    for p in items:
        if p and p not in uniq:
            uniq.append(p)
    try:
        with open(PROXY_FILE, "w", encoding="utf-8") as f:
            json.dump(uniq, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def load_all() -> Tuple[Settings, List[ScheduleItem]]:
    s = Settings()
    scheds: List[ScheduleItem] = []
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                obj = json.load(f)
            s = Settings(**{k: v for k, v in obj.items() if k in Settings().__dict__.keys()})
            for it in obj.get('_schedules', []):
                scheds.append(ScheduleItem(**it))
    except Exception:
        pass
    if not s.chrome_binary: s.chrome_binary = guess_chrome_binary()
    if not s.firefox_binary: s.firefox_binary = guess_firefox_binary()
    if not s.edge_binary:   s.edge_binary   = guess_edge_binary()
    if not s.brave_binary:  s.brave_binary  = guess_brave_binary()
    if not s.opera_binary:  s.opera_binary  = guess_opera_binary()

    if not any(x.group_name=="Gündüz" for x in scheds):
        scheds.append(ScheduleItem(time_hhmm="10:00", group_name="Gündüz", enabled=True, weekdays=list(range(0,5))))
    if not any(x.group_name=="Gece" for x in scheds):
        scheds.append(ScheduleItem(time_hhmm="22:00", group_name="Gece", enabled=True, weekdays=list(range(0,5))))
    return s, scheds

def save_all(settings: Settings, schedules: List[ScheduleItem]):
    try:
        data = asdict(settings); data['_schedules'] = [asdict(x) for x in schedules]
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def log_append(widget: QTextEdit, text: str):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] {text}"
    try:
        doc = widget.document()
        if doc.blockCount() > 1000:
            cursor = widget.textCursor()
            cursor.movePosition(cursor.Start)
            cursor.movePosition(cursor.Down, cursor.KeepAnchor, 200)
            cursor.removeSelectedText()
            cursor.deleteChar()
    except Exception:
        pass
    widget.append(line)
    try:
        if not hasattr(widget, "_log_buf"): widget._log_buf = []
        widget._log_buf.append(line)
        if len(widget._log_buf) >= 5:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write("\n".join(widget._log_buf) + "\n")
            widget._log_buf.clear()
    except Exception:
        pass

# ---------- UA Yardımcıları ----------
def default_ua_for(browser: str) -> str:
    if browser in ("chrome", "brave", "opera"):
        return ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36")
    if browser == "edge":
        return ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0")
    if browser == "firefox":
        return ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
                "Gecko/20100101 Firefox/125.0")
    return ""

def _ua_pick(manual: str, mode: str, browser_key: str) -> str:
    if (mode or "Auto") == "Manual" and manual:
        return manual
    return default_ua_for(browser_key)

# ---------- Proxy Yardımcıları ----------
def normalize_proxy(p: str) -> str:
    if not p: return ""
    p = p.strip()
    if p.startswith(("http://","https://","socks5://","socks5h://","socks4://")):
        return p
    return f"http://{p}"

def requests_proxy_dict(p: str) -> dict:
    p = normalize_proxy(p)
    return {"http": p, "https": p} if p else {}

def probe_proxy_https_youtube(p: str, timeout: int = 10) -> bool:
    try:
        r = requests.get("https://www.youtube.com/generate_204",
                         proxies=requests_proxy_dict(p),
                         timeout=timeout, allow_redirects=False)
        return r.status_code in (204, 200, 301, 302)
    except Exception:
        return False

# --- UZAK KAYNAK HARİTASI ---
GITHUB_PROXY_SOURCES = {
    # GH1: TheSpeedX/PROXY-List
    "GH1": {
        "HTTP":   "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "SOCKS4": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "SOCKS5": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    },
    # GH2: monosans/proxy-list
    "GH2": {
        "HTTP":   "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "SOCKS4": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        "SOCKS5": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    },
    # GH3: clarketm/proxy-list (karışık HTTP ağırlık)
    "GH3": {
        "HTTP":   "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "SOCKS4": None,
        "SOCKS5": None,
    }
}

def _fetch_lines(url: str, timeout: int = 20) -> List[str]:
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        lines = [x.strip() for x in r.text.splitlines() if x.strip()]
        return lines
    except Exception:
        return []

def _parse_proxies_from_lines(lines: List[str], expected_type: str) -> List[str]:
    out = []
    scheme = "http" if expected_type == "HTTP" else ("socks4" if expected_type == "SOCKS4" else "socks5")
    for line in lines:
        part = line.split()[0]
        if "://" in part:
            out.append(part)
            continue
        if ":" in part:
            host, port = part.rsplit(":", 1)
            if host and port.isdigit():
                out.append(f"{scheme}://{host}:{port}")
    return out

def fetch_remote_proxies(source_mode: str, proxy_type: str, optional_url: str = "") -> List[str]:
    if source_mode == "Manual":
        return []
    if source_mode == "Optional":
        if not optional_url:
            return []
        lines = _fetch_lines(optional_url)
        return _parse_proxies_from_lines(lines, proxy_type)
    mapping = GITHUB_PROXY_SOURCES.get(source_mode, {})
    url = mapping.get(proxy_type)
    if not url:
        return []
    lines = _fetch_lines(url)
    return _parse_proxies_from_lines(lines, proxy_type)

# ---------- Proxy Rotatör ----------
class ProxyRotator:
    def __init__(self, proxies: List[str], failover_secs: int = 120):
        self.proxies = [normalize_proxy(x) for x in (proxies or [])]
        self.failover_secs = max(10, int(failover_secs or 120))
        self.idx = 0

    def has_list(self) -> bool:
        return len(self.proxies) > 0

    def current(self) -> str:
        if not self.proxies: return ""
        return self.proxies[self.idx % len(self.proxies)]

    def next(self) -> str:
        if not self.proxies: return ""
        self.idx = (self.idx + 1) % len(self.proxies)
        return self.current()

# ---------- URL listesi persist ----------
def save_url_list_from_widget(list_widget: QListWidget):
    data = []
    for i in range(list_widget.count()):
        it = list_widget.item(i)
        (url, mins) = it.data(Qt.UserRole) or (it.text(), 1)
        group = it.data(Qt.UserRole+1) or ""
        data.append({"url": url, "minutes": int(mins), "group": group})
    try:
        with open(URLLIST_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def load_url_list_to_widget(list_widget: QListWidget, make_item_fn):
    try:
        if not os.path.exists(URLLIST_FILE):
            return 0
        with open(URLLIST_FILE, "r", encoding="utf-8") as f:
            arr = json.load(f)
        list_widget.clear()
        for obj in arr or []:
            u = obj.get("url","").strip()
            m = int(obj.get("minutes", 1))
            g = obj.get("group","")
            if u:
                list_widget.addItem(make_item_fn(u, m, g))
        return len(arr or [])
    except Exception:
        return 0

# ---------- SMTP ----------
def send_smtp_mail(subject: str, body: str, log_widget: Optional[QTextEdit] = None):
    cfg = load_smtp()
    if not cfg.enabled or not cfg.user or not cfg.password or not cfg.to_addr:
        return False
    try:
        msg = MIMEText(body, _charset="utf-8")
        msg["Subject"] = subject
        msg["From"] = cfg.user
        msg["To"] = cfg.to_addr

        if cfg.use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(cfg.host, cfg.port, context=context, timeout=30) as s:
                s.login(cfg.user, cfg.password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(cfg.host, cfg.port, timeout=30) as s:
                s.ehlo()
                if cfg.use_tls: s.starttls()
                s.login(cfg.user, cfg.password)
                s.send_message(msg)
        if log_widget: log_append(log_widget, "SMTP: Bildirim gönderildi.")
        return True
    except Exception as e:
        if log_widget: log_append(log_widget, f"SMTP hata: {e}")
        return False

# ---------- Tarayıcı Denetleyicisi ----------
class BrowserController:
    def __init__(self, s: Settings, screen_rect, forced_proxy: str = ""):
        self.s = s
        self.screen_rect = screen_rect  # (x,y,w,h)
        self._forced_proxy = normalize_proxy(forced_proxy.strip())
        self.chrome: Optional[webdriver.Chrome] = None
        self.firefox: Optional[webdriver.Firefox] = None
        self.edge: Optional[webdriver.Edge] = None
        self.brave: Optional[webdriver.Chrome] = None
        self.opera: Optional[webdriver.Chrome] = None

        try:
            use_any_chromium = s.use_chrome or s.use_brave or s.use_opera
            self._chromium_driver = ChromeDriverManager().install() if use_any_chromium else None
        except Exception:
            self._chromium_driver = None
        try:
            self._gecko_driver = GeckoDriverManager().install() if s.use_firefox else None
        except Exception:
            self._gecko_driver = None
        try:
            self._edge_driver = EdgeChromiumDriverManager().install() if s.use_edge else None
        except Exception:
            self._edge_driver = None

    def _pick_proxy(self) -> str:
        return self._forced_proxy or (normalize_proxy(self.s.http_proxy.strip()) if self.s.http_proxy else "")

    def _apply_common_chrome_opts(self, opts: ChromeOptions, browser_key: str):
        ua = _ua_pick(self.s.user_agent, self.s.ua_mode, browser_key)
        if ua: opts.add_argument(f"--user-agent={ua}")
        proxy_val = self._pick_proxy()
        if proxy_val:
            opts.add_argument(f"--proxy-server={proxy_val}")
            opts.add_argument("--disable-quic")
            opts.add_argument("--proxy-bypass-list=<-loopback>")
        opts.add_argument("--no-first-run")
        opts.add_argument("--no-default-browser-check")
        opts.add_argument("--disable-extensions")
        opts.add_argument("--disable-notifications")
        opts.add_argument("--disable-background-networking")
        opts.add_argument("--disable-renderer-backgrounding")
        opts.add_argument("--disable-background-timer-throttling")
        opts.add_argument("--autoplay-policy=no-user-gesture-required")
        try:
            opts.set_capability("pageLoadStrategy", "eager")
        except Exception:
            pass
        try:
            opts.add_experimental_option("prefs", {
                "profile.default_content_setting_values.notifications": 2,
                "credentials_enable_service": False,
                "profile.password_manager_enabled": False
            })
        except Exception:
            pass

    def _apply_common_firefox_opts(self, opts: FirefoxOptions):
        ua = _ua_pick(self.s.user_agent, self.s.ua_mode, "firefox")
        if ua: opts.set_preference("general.useragent.override", ua)
        proxy_val = self._pick_proxy()
        if proxy_val:
            try:
                opts.set_preference("network.proxy.type", 1)
                if proxy_val.startswith("socks5") or proxy_val.startswith("socks4"):
                    pv = proxy_val.replace("socks5h://","").replace("socks5://","").replace("socks4://","")
                    host, port = pv.split(":")
                    opts.set_preference("network.proxy.socks", host)
                    opts.set_preference("network.proxy.socks_port", int(port))
                else:
                    pv = proxy_val.replace("http://","").replace("https://","")
                    host, port = pv.split(":")
                    opts.set_preference("network.proxy.http", host)
                    opts.set_preference("network.proxy.http_port", int(port))
                    opts.set_preference("network.proxy.ssl", host)
                    opts.set_preference("network.proxy.ssl_port", int(port))
                opts.set_preference("network.proxy.no_proxies_on", "")
                opts.set_preference("network.proxy.share_proxy_settings", True)
            except Exception:
                pass
        if self.s.firefox_binary: opts.binary_location = self.s.firefox_binary
        opts.set_preference("media.autoplay.default", 0)
        opts.set_preference("media.block-autoplay-until-in-foreground", False)
        opts.set_preference("media.autoplay.blocking_policy", 0)
        opts.set_preference("browser.tabs.remote.autostart", True)
        opts.set_preference("dom.ipc.processCount", 1)
        try:
            opts.set_capability("pageLoadStrategy", "eager")
        except Exception:
            pass

    def _apply_common_edge_opts(self, opts: EdgeOptions):
        ua = _ua_pick(self.s.user_agent, self.s.ua_mode, "edge")
        if ua: opts.add_argument(f"--user-agent={ua}")
        proxy_val = self._pick_proxy()
        if proxy_val:
            opts.add_argument(f"--proxy-server={proxy_val}")
            opts.add_argument("--disable-quic")
            opts.add_argument("--proxy-bypass-list=<-loopback>")
        if self.s.edge_binary: opts.binary_location = self.s.edge_binary
        opts.add_argument("--no-first-run")
        opts.add_argument("--no-default-browser-check")
        opts.add_argument("--disable-extensions")
        opts.add_argument("--disable-notifications")
        opts.add_argument("--disable-background-networking")
        opts.add_argument("--disable-renderer-backgrounding")
        opts.add_argument("--disable-background-timer-throttling")
        opts.add_argument("--autoplay-policy=no-user-gesture-required")
        try:
            opts.set_capability("pageLoadStrategy", "eager")
        except Exception:
            pass

    def start(self):
        if self.s.use_chrome and not self.chrome:
            ch_opts = ChromeOptions(); self._apply_common_chrome_opts(ch_opts, "chrome")
            if self.s.chrome_binary: ch_opts.binary_location = self.s.chrome_binary
            self.chrome = webdriver.Chrome(service=ChromeService(self._chromium_driver), options=ch_opts); self.chrome.get("about:blank")
        if self.s.use_firefox and not self.firefox:
            ff_opts = FirefoxOptions(); self._apply_common_firefox_opts(ff_opts)
            self.firefox = webdriver.Firefox(service=FirefoxService(self._gecko_driver), options=ff_opts); self.firefox.get("about:blank")
        if self.s.use_edge and not self.edge:
            ed_opts = EdgeOptions(); self._apply_common_edge_opts(ed_opts)
            self.edge = webdriver.Edge(service=EdgeService(self._edge_driver), options=ed_opts); self.edge.get("about:blank")
        if self.s.use_brave and not self.brave:
            br_opts = ChromeOptions(); self._apply_common_chrome_opts(br_opts, "brave")
            if self.s.brave_binary: br_opts.binary_location = self.s.brave_binary
            self.brave = webdriver.Chrome(service=ChromeService(self._chromium_driver), options=br_opts); self.brave.get("about:blank")
        if self.s.use_opera and not self.opera:
            op_opts = ChromeOptions(); self._apply_common_chrome_opts(op_opts, "opera")
            if self.s.opera_binary: op_opts.binary_location = self.s.opera_binary
            self.opera = webdriver.Chrome(service=ChromeService(self._chromium_driver), options=op_opts); self.opera.get("about:blank")
        self.arrange_windows()

    def stop(self):
        for drv_name in ("chrome","firefox","edge","brave","opera"):
            drv = getattr(self, drv_name)
            if drv:
                try: drv.quit()
                except Exception: pass
                setattr(self, drv_name, None)

    def drivers(self) -> List[Tuple[str, object]]:
        out = []
        for name in ("chrome","firefox","edge","brave","opera"):
            d = getattr(self, name)
            if d: out.append((name, d))
        return out

    def arrange_windows(self):
        x, y, w, h = self.screen_rect
        drvs = self.drivers()
        n = len(drvs)
        if n == 0: return
        layout = self.s.window_layout or "Auto"
        if layout == "Auto":
            layout = "2x2" if n >= 4 else ("1x2" if n == 2 else "1x1")
        try:
            if layout == "2x2":
                cols, rows = 2, 2
                cw, ch = w // cols, h // rows
                for i, (_, d) in enumerate(drvs[:4]):
                    cx, cy = i % cols, i // cols
                    d.set_window_rect(x + cx*cw, y + cy*ch, cw, ch)
            elif layout == "1x2":
                cw = w // 2
                for i, (_, d) in enumerate(drvs[:2]):
                    d.set_window_rect(x + i*cw, y, cw, h)
                if n == 3:
                    drvs[2][1].set_window_rect(x, y + h//2, w, h//2)
            else:  # 1x1
                drvs[0][1].set_window_rect(x, y, w, h)
        except Exception:
            pass

    def _wait_ready(self, drv, timeout=20):
        try:
            WebDriverWait(drv, timeout).until(
                lambda d: d.execute_script("return document.readyState") in ("interactive", "complete")
            )
            return True
        except Exception:
            return False

    def _yt_autoplay_url(self, url: str) -> str:
        try:
            vid = ""
            if "youtube.com/watch" in url:
                u = urlparse(url); qs = parse_qs(u.query); vid = (qs.get("v") or [""])[0]
            elif "youtu.be/" in url:
                path = urlparse(url).path.strip("/"); vid = path.split("/")[0]
            elif "youtube.com/shorts/" in url:
                path = urlparse(url).path; vid = path.split("/shorts/")[1].split("/")[0]
            else:
                return url
            if not vid: return url
            base = f"https://www.youtube.com/embed/{vid}"
            params = {
                "autoplay": "1","mute": "1","enablejsapi": "1","playsinline": "1",
                "rel": "0","modestbranding": "1","controls": "1"
            }
            return base + "?" + urlencode(params)
        except Exception:
            return url

    def _try_play_youtube(self, drv, unmute_after=0):
        js_start = r"""
        (function(){
          const v = document.querySelector('video');
          if (!v) return "no-video";
          try {
            v.muted = true;
            var p = v.play();
            if (p && p.catch) p.catch(()=>{});
            return "playing-muted";
          } catch(e) { return "play-error"; }
        })();
        """
        try: drv.execute_script(js_start)
        except Exception: pass
        try:
            drv.execute_script("""
              (function(){
                if (window.__yt_keep_playing__) return;
                window.__yt_keep_playing__ = setInterval(function(){
                  try {
                    var v = document.querySelector('video');
                    if (!v) return;
                    if ((v.paused || v.readyState < 2) && (!v.ended)) {
                      var p = v.play();
                      if (p && p.catch) p.catch(()=>{});
                    }
                  } catch(e) {}
                }, 800);
              })();
            """)
        except Exception: pass
        try:
            drv.execute_script("""
              (function(){
                const btn = document.querySelector('button.ytp-large-play-button') ||
                            document.querySelector('.ytp-play-button');
                if (btn) btn.click();
              })();
            """)
        except Exception: pass
        if unmute_after and unmute_after > 0:
            try:
                time.sleep(unmute_after)
                drv.execute_script("""
                  (function(){
                    const v = document.querySelector('video');
                    if (!v) return;
                    v.muted = false; v.volume = 0.6;
                    if (v.paused) { var p = v.play(); if (p && p.catch) p.catch(()=>{}); }
                  })();
                """)
            except Exception: pass

    def open_url_in_active_tab(self, url: str) -> List[Tuple[str, str]]:
        opened = []
        nav_url = self._yt_autoplay_url(url)
        for name, drv in self.drivers():
            for attempt in range(1, 2+1):
                try:
                    drv.get(nav_url)
                    self._wait_ready(drv, timeout=20)
                    try: drv.execute_script("window.focus();")
                    except Exception: pass
                    time.sleep(0.6)
                    if "youtube.com" in nav_url or "youtu.be" in nav_url:
                        self._try_play_youtube(drv, unmute_after=0)
                        for _ in range(6):
                            try:
                                paused = drv.execute_script("const v=document.querySelector('video'); return v? v.paused : False;")
                                if paused:
                                    self._try_play_youtube(drv, unmute_after=0); time.sleep(1.0)
                                else: break
                            except Exception: break
                    opened.append((name, drv.current_window_handle))
                    break
                except Exception:
                    if attempt == 2:
                        raise
                    try: time.sleep(1.5); drv.refresh()
                    except Exception: pass
        return opened

# ---------- VpnManager (OpenVPN Community) ----------
class VpnManager:
    def __init__(self, openvpn_exe: str, username: str, password: str,
                 connect_timeout: int = 60, stop_timeout: int = 10,
                 log_callback=None):
        self.openvpn_exe = openvpn_exe
        self.username = username
        self.password = password
        self.connect_timeout = connect_timeout
        self.stop_timeout = stop_timeout
        self.proc = None
        self.log_callback = log_callback
        self.current_log = None
        self.current_auth = None
        self.current_ovpn = None

    def _log(self, msg: str):
        if self.log_callback:
            self.log_callback(msg)

    def _create_auth_file(self) -> str:
        fd, path = tempfile.mkstemp(prefix="ovpn_auth_", suffix=".txt")
        os.close(fd)
        with open(path, "w", encoding="ascii") as f:
            f.write(self.username + "\n")
            f.write(self.password + "\n")
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return path

    def connect(self, ovpn_path: str) -> bool:
        self.disconnect()
        self.current_ovpn = ovpn_path
        self.current_auth = self._create_auth_file()
        log_fd, log_path = tempfile.mkstemp(prefix="ovpn_log_", suffix=".log")
        os.close(log_fd)
        self.current_log = log_path
        if not os.path.exists(self.openvpn_exe):
            self._log("[VPN] openvpn.exe bulunamadı.")
            raise RuntimeError("openvpn.exe bulunamadı")

        args = [
            self.openvpn_exe,
            "--config", ovpn_path,
            "--auth-user-pass", self.current_auth,
            "--log", self.current_log,
            "--verb", "3",
            "--pull-filter", "ignore", "block-outside-dns"
        ]
        CREATE_NO_WINDOW = 0x08000000
        try:
            self.proc = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                creationflags=CREATE_NO_WINDOW
            )
        except Exception as e:
            self._log(f"[VPN] openvpn.exe başlatılamadı: {e}")
            self.cleanup_files()
            raise

        # Bağlantı bekle
        start = time.time()
        last_size = 0
        while time.time() - start < self.connect_timeout:
            time.sleep(1.5)
            try:
                if self.proc and self.proc.poll() is not None:
                    return False
                if os.path.exists(self.current_log):
                    size = os.path.getsize(self.current_log)
                    if size != last_size:
                        last_size = size
                        with open(self.current_log, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            if "Initialization Sequence Completed" in content:
                                return True
                            if "AUTH_FAILED" in content:
                                return False
                            if "TLS Error" in content:
                                pass
            except Exception:
                pass
        return False

    def disconnect(self):
        if self.proc:
            try:
                self.proc.terminate()
                t0 = time.time()
                while time.time() - t0 < self.stop_timeout:
                    if self.proc.poll() is not None:
                        break
                    time.sleep(0.5)
                if self.proc.poll() is None:
                    self.proc.kill()
            except Exception:
                pass
            self.proc = None
        self.cleanup_files()

    def cleanup_files(self):
        for p in [self.current_auth, self.current_log]:
            try:
                if p and os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        self.current_auth = None
        self.current_log = None

    def current_vpn_name(self) -> str:
        if not self.current_ovpn: return "-"
        return os.path.splitext(os.path.basename(self.current_ovpn))[0]

# ---------- Sinyaller & Worker ----------
class WorkerSignals(QObject):
    moved = Signal(str)
    finished = Signal()
    status = Signal(str)
    progress = Signal(int, int, str)  # elapsed_sec, total_sec, url

class RotatorWorker(threading.Thread):
    def __init__(self, urls_with_minutes: List[Tuple[str,int]], settings: Settings, signals: WorkerSignals, screen_rect):
        super().__init__(daemon=True)
        self.urls_with_minutes = urls_with_minutes
        self.settings = settings
        self.signals = signals
        self._pause = threading.Event(); self._pause.clear()
        self._stop = threading.Event(); self._stop.clear()
        self.controller: Optional[BrowserController] = None
        self.screen_rect = screen_rect

        # Proxy listesi belirleme
        manual_list = load_proxies()  # proxy.json
        remote_list = fetch_remote_proxies(
            source_mode=self.settings.proxy_source_mode,
            proxy_type=self.settings.proxy_type,
            optional_url=self.settings.proxy_optional_url
        )

        if self.settings.proxy_enabled:
            if self.settings.proxy_source_mode == "Manual":
                active_list = manual_list
            else:
                active_list = remote_list or manual_list
        else:
            active_list = []

        self.proxy_rotator = ProxyRotator(active_list, failover_secs=self.settings.proxy_failover_secs)

        # URL ilerleme için en sonda taşımak amacıyla snapshot
        self._all_urls_snapshot = list(self.urls_with_minutes)

    def _start_controller(self, forced_proxy: str = ""):
        if self.controller:
            try: self.controller.stop()
            except Exception: pass
        self.controller = BrowserController(self.settings, self.screen_rect, forced_proxy=forced_proxy)
        self.controller.start()

    def _send_mail(self, title: str, html: str):
        send_smtp_mail(title, html, log_widget=None)

    def _vpn_files(self) -> List[str]:
        ovpn_dir = (self.settings.vpn_ovpn_dir or "").strip()
        if not ovpn_dir or not os.path.isdir(ovpn_dir):
            return []
        files = [os.path.join(ovpn_dir, f) for f in os.listdir(ovpn_dir) if f.lower().endswith(".ovpn")]
        files.sort()
        return files

    def _run_urls_once(self) -> List[dict]:
        """
        URL’leri bir tur çalıştırır; her URL için {url, minutes, success, browsers[list[str]]} döner.
        Proxy aktifteyse mevcut mantıkla probe/deneme yapar.
        """
        results = []

        def try_with_proxy(pval: str) -> Tuple[bool, List[str]]:
            opened_browsers = []
            if pval:
                self.signals.status.emit(f"Proxy probe: {pval} (HTTPS test)")
                if not probe_proxy_https_youtube(pval, timeout=min(12, self.settings.proxy_failover_secs)):
                    self.signals.status.emit(f"Proxy probe başarısız: {pval}")
                    return False, opened_browsers
            self._start_controller(forced_proxy=pval)
            try:
                opened = self.controller.open_url_in_active_tab(url)
                opened_browsers = [name for (name, _) in opened]
                waited = 0
                while waited < self.settings.proxy_failover_secs:
                    if self._stop.is_set(): return False, opened_browsers
                    any_ready = False
                    for _, drv in self.controller.drivers():
                        try:
                            rs = drv.execute_script("return document.readyState")
                            body_len = drv.execute_script("return (document.body && document.body.innerText) ? document.body.innerText.length : 0;")
                            if rs in ("interactive", "complete") and body_len >= 0:
                                any_ready = True; break
                        except Exception:
                            pass
                    if any_ready:
                        return True, opened_browsers
                    time.sleep(2); waited += 2
                return False, opened_browsers
            except Exception:
                return False, opened_browsers

        for (url, mins) in list(self.urls_with_minutes):
            if self._stop.is_set(): break
            while self._pause.is_set() and not self._stop.is_set(): time.sleep(0.2)

            duration_total = max(1, (mins or self.settings.minutes)) * 60
            self.signals.status.emit(f"Açılıyor: {url} — {int(duration_total/60)} dk")

            success_this_url = False
            used_browsers: List[str] = []

            if self.settings.proxy_enabled and self.proxy_rotator.has_list():
                tried_count = 0
                max_try = len(self.proxy_rotator.proxies)
                while tried_count < max_try and not success_this_url:
                    cur = self.proxy_rotator.current()
                    self.signals.status.emit(f"Proxy deneniyor: {cur}")
                    ok, names = try_with_proxy(cur)
                    if ok:
                        success_this_url = True
                        used_browsers = names
                        self.signals.status.emit(f"Proxy OK: {cur}")
                    else:
                        self.signals.status.emit(f"Proxy başarısız: {cur} — sıradaki denenecek")
                        self.proxy_rotator.next()
                        tried_count += 1
                if not success_this_url:
                    self.signals.status.emit("Tüm proxy’ler başarısız. Proxysiz deneniyor…")
                    ok, names = try_with_proxy("")
                    success_this_url = ok; used_browsers = names
            else:
                p = normalize_proxy((self.settings.http_proxy or "").strip())
                if p:
                    self.signals.status.emit(f"Tek proxy kullanılıyor: {p}")
                    ok, names = try_with_proxy(p)
                    if not ok:
                        self.signals.status.emit("Tek proxy başarısız, proxysiz deneniyor…")
                        ok2, names2 = try_with_proxy("")
                        success_this_url = ok2; used_browsers = names2
                    else:
                        success_this_url = True; used_browsers = names
                else:
                    ok, names = try_with_proxy("")
                    success_this_url = ok; used_browsers = names

            if not success_this_url:
                self.signals.status.emit(f"URL açılamadı (proxy/bağlantı hatası): {url}")
                # moved sinyalini EN SON (tüm VPN’ler bitince) atacağız
                results.append({"url": url, "minutes": int(duration_total/60), "success": False, "browsers": []})
                continue

            start_ts = time.time()
            while True:
                if self._stop.is_set(): break
                while self._pause.is_set() and not self._stop.is_set():
                    time.sleep(0.2)
                elapsed = int(time.time() - start_ts)
                if elapsed > duration_total: break
                if elapsed % 5 == 0:
                    self.signals.progress.emit(elapsed, duration_total, url)
                time.sleep(min(5, max(0, duration_total - elapsed)))

            results.append({"url": url, "minutes": int(duration_total/60), "success": True, "browsers": used_browsers})

        try:
            if self.controller: self.controller.stop()
        except Exception:
            pass

        return results

    def run(self):
        # E-posta kısa yardımcıları
        def mail_vpn_connected(name: str):
            self._send_mail(f"[BOT] VPN Bağlandı: {name}",
                            f"<h3>VPN Bağlandı</h3><p><b>VPN:</b> {name}</p><p>{time.ctime()}</p>")
        def mail_vpn_disconnected(name: str):
            self._send_mail(f"[BOT] VPN Kapatıldı: {name}",
                            f"<h3>VPN Kapatıldı</h3><p><b>VPN:</b> {name}</p><p>{time.ctime()}</p>")
        def mail_vpn_error(name: str, err: str):
            self._send_mail(f"[BOT] VPN Hata: {name}",
                            f"<h3>VPN Bağlantı Hatası</h3><p><b>VPN:</b> {name}</p><pre>{err}</pre><p>{time.ctime()}</p>")
        def mail_vpn_summary(name: str, results: List[dict]):
            if not results: return
            rows = []
            for r in results:
                rows.append(
                    f"<tr><td>{r['url']}</td><td>{', '.join(r['browsers']) or '-'}</td>"
                    f"<td align='right'>{r['minutes']}</td><td>{'OK' if r['success'] else 'FAIL'}</td></tr>"
                )
            html = f"""
            <h3>VPN Oturum Özeti</h3>
            <p><b>VPN:</b> {name}</p>
            <table border="1" cellpadding="6" cellspacing="0">
                <tr><th>URL</th><th>Tarayıcılar</th><th>Süre (dk)</th><th>Durum</th></tr>
                {''.join(rows)}
            </table>
            <p>{time.ctime()}</p>
            """
            self._send_mail(f"[BOT] VPN Özeti: {name}", html)

        # --- VPN rotasyon moduna göre akış ---
        use_vpn = bool(self.settings.vpn_rotate_enabled and
                       os.path.isfile(self.settings.openvpn_exe) and
                       os.path.isdir(self.settings.vpn_ovpn_dir))
        ovpn_files = self._vpn_files() if use_vpn else []

        if use_vpn and ovpn_files:
            # Her .ovpn için tam URL turu
            for ovpn in ovpn_files:
                if self._stop.is_set(): break
                vpn = VpnManager(
                    openvpn_exe=self.settings.openvpn_exe,
                    username=self.settings.vpn_username,
                    password=self.settings.vpn_password,
                    connect_timeout=self.settings.vpn_connect_timeout_sec,
                    stop_timeout=self.settings.vpn_stop_timeout_sec,
                    log_callback=lambda s: self.signals.status.emit(s)
                )
                vpn_name = os.path.splitext(os.path.basename(ovpn))[0]
                self.signals.status.emit(f"=== VPN başlatılıyor: {vpn_name} ===")
                ok = False; err_txt = ""
                try:
                    ok = vpn.connect(ovpn)
                except Exception as e:
                    ok = False; err_txt = str(e)

                if not ok:
                    self.signals.status.emit(f"[VPN] Bağlantı hatası: {vpn_name} → sıradaki .ovpn’a geçiliyor.")
                    mail_vpn_error(vpn_name, err_txt or "Bağlantı zaman aşımı / openvpn.exe hatası")
                    continue

                # Bağlandı maili
                mail_vpn_connected(vpn_name)

                # URL’leri bir tur çalıştır
                results = self._run_urls_once()

                # Özet mail
                mail_vpn_summary(vpn_name, results)

                # VPN kapat
                vpn.disconnect()
                mail_vpn_disconnected(vpn_name)

            # Tüm VPN turları bitince, sol listedeki öğeleri sağa taşı (1 kez)
            for (url, _m) in self._all_urls_snapshot:
                self.signals.moved.emit(url)

            self.signals.finished.emit()
            self._send_mail(f"{APP_NAME}: Görev tamamlandı", "Tüm VPN profilleri işlendi, program tamamlandı.")
            return

        # ---- VPN kullanılmıyorsa eski davranış: tek tur ----
        self._start_controller(forced_proxy="")
        results = self._run_urls_once()
        for (url, _m) in self._all_urls_snapshot:
            self.signals.moved.emit(url)
        self.signals.finished.emit()
        self._send_mail(f"{APP_NAME}: Görev tamamlandı (VPN yok)", "URL listesi tek tur çalıştırıldı.")

    def pause(self, yes: bool): self._pause.set() if yes else self._pause.clear()
    def stop(self): self._stop.set()

# ---------- Gruplar Dialog ----------
class GroupsDialog(QDialog):
    def __init__(self, parent: 'MainWindow'):
        super().__init__(parent)
        self.setWindowTitle("Gruplar")
        self.parent_ref = parent
        self._list = QListWidget()
        self._in = QLineEdit(); self._in.setPlaceholderText("Yeni grup adı")
        self.btn_add = QPushButton("Grup Ekle")
        self.btn_del = QPushButton("Grup Sil")
        btn_close = QDialogButtonBox(QDialogButtonBox.Close)
        btn_close.rejected.connect(self.reject); btn_close.accepted.connect(self.accept)

        for g in self.parent_ref.groups: self._list.addItem(g)
        self._list.currentRowChanged.connect(self._update_delete_state)
        self.btn_add.clicked.connect(self._add); self.btn_del.clicked.connect(self._del)

        lay = QVBoxLayout()
        lay.addWidget(self._list)
        bar = QHBoxLayout(); bar.addWidget(self._in); bar.addWidget(self.btn_add); bar.addWidget(self.btn_del)
        lay.addLayout(bar); lay.addWidget(btn_close)
        self.setLayout(lay)
        self._update_delete_state()

    def _update_delete_state(self, *_):
        row = self._list.currentRow()
        name = self._list.item(row).text() if row >= 0 else ""
        self.btn_del.setEnabled(name not in DEFAULT_GROUPS)

    def _add(self):
        name = self._in.text().strip()
        if not name: return
        if name in DEFAULT_GROUPS:
            QMessageBox.information(self, "Bilgi", "Gündüz/Gece grupları zaten mevcut.")
            return
        if not any(self._list.item(i).text()==name for i in range(self._list.count())):
            self._list.addItem(name); self._in.clear()
            self.parent_ref.groups.append(name); save_groups(self.parent_ref.groups); self.parent_ref.refresh_group_completer()

    def _del(self):
        row = self._list.currentRow()
        if row < 0: return
        name = self._list.item(row).text()
        if name in DEFAULT_GROUPS:
            QMessageBox.information(self, "Bilgi", "Gündüz ve Gece silinemez."); return
        self._list.takeItem(row)
        try:
            self.parent_ref.groups.remove(name)
        except ValueError:
            pass
        save_groups(self.parent_ref.groups); self.parent_ref.refresh_group_completer()

# ---------- Proxy Dialog ----------
class ProxyDialog(QDialog):
    def __init__(self, parent: 'MainWindow'):
        super().__init__(parent)
        self.setWindowTitle("Proxyler")
        self._list = QListWidget()
        self._in = QLineEdit(); self._in.setPlaceholderText("http://host:port veya socks5://host:port veya socks4://host:port")
        self.btn_add = QPushButton("Ekle")
        self.btn_del = QPushButton("Sil")
        self.btn_del_all = QPushButton("Tümünü Sil")
        btn_close = QDialogButtonBox(QDialogButtonBox.Close)
        btn_close.rejected.connect(self.reject); btn_close.accepted.connect(self.accept)

        # Uzak kaynaktan çekme modülü
        self.cmb_remote_src = QComboBox(); self.cmb_remote_src.addItems(["GH1", "GH2", "GH3", "Optional"])
        self.cmb_remote_type = QComboBox(); self.cmb_remote_type.addItems(["HTTP", "SOCKS4", "SOCKS5"])
        self.ed_remote_url = QLineEdit(); self.ed_remote_url.setPlaceholderText("Optional seçersen buraya URL gir (ip:port satır satır)")
        self.btn_fetch = QPushButton("Uzak Kaynaktan İndir → Listeye Ekle")
        self.btn_fetch.clicked.connect(self._fetch_to_list)

        for p in load_proxies(): self._list.addItem(p)
        self.btn_add.clicked.connect(self._add); self.btn_del.clicked.connect(self._del); self.btn_del_all.clicked.connect(self._del_all)

        lay = QVBoxLayout()
        lay.addWidget(self._list)

        fetch_bar = QHBoxLayout()
        fetch_bar.addWidget(QLabel("Kaynak:")); fetch_bar.addWidget(self.cmb_remote_src)
        fetch_bar.addWidget(QLabel("Tip:")); fetch_bar.addWidget(self.cmb_remote_type)
        fetch_bar.addWidget(self.ed_remote_url); fetch_bar.addWidget(self.btn_fetch)
        lay.addLayout(fetch_bar)

        bar = QHBoxLayout(); bar.addWidget(self._in); bar.addWidget(self.btn_add); bar.addWidget(self.btn_del); bar.addWidget(self.btn_del_all)
        lay.addLayout(bar); lay.addWidget(btn_close)
        self.setLayout(lay)

    def _add(self):
        p = normalize_proxy(self._in.text().strip())
        if not p: return
        allp = [self._list.item(i).text() for i in range(self._list.count())]
        if p not in allp:
            self._list.addItem(p); self._in.clear(); save_proxies([self._list.item(i).text() for i in range(self._list.count())])

    def _del(self):
        row = self._list.currentRow()
        if row < 0: return
        self._list.takeItem(row)
        save_proxies([self._list.item(i).text() for i in range(self._list.count())])

    def _del_all(self):
        self._list.clear(); save_proxies([])

    def _fetch_to_list(self):
        mode = self.cmb_remote_src.currentText()
        ptype = self.cmb_remote_type.currentText()
        url = self.ed_remote_url.text().strip()
        if mode != "Optional":
            url = ""
        items = fetch_remote_proxies(mode, ptype, url)
        if not items:
            QMessageBox.warning(self, "Hata", "Uzak listede kayıt bulunamadı veya erişilemedi.")
            return
        existing = { self._list.item(i).text() for i in range(self._list.count()) }
        new_count = 0
        for p in items:
            if p not in existing:
                self._list.addItem(p)
                existing.add(p)
                new_count += 1
        save_proxies([self._list.item(i).text() for i in range(self._list.count())])
        QMessageBox.information(self, "Tamam", f"Listeye {new_count} yeni proxy eklendi.")

# ---------- SMTP Dialog ----------
class SmtpDialog(QDialog):
    def __init__(self, parent: 'MainWindow'):
        super().__init__(parent)
        self.setWindowTitle("SMTP Ayarları")
        self.cfg = load_smtp()

        self._enabled = QCheckBox("SMTP bildirimleri aktif")
        self._host = QLineEdit(); self._port = QSpinBox(); self._port.setRange(1,65535)
        self._user = QLineEdit(); self._pass = QLineEdit(); self._pass.setEchoMode(QLineEdit.Password)
        self._to = QLineEdit()
        self._tls = QCheckBox("STARTTLS kullan"); self._ssl = QCheckBox("SSL kullan (465)")
        self._enabled.setChecked(self.cfg.enabled)
        self._host.setText(self.cfg.host); self._port.setValue(self.cfg.port)
        self._user.setText(self.cfg.user); self._pass.setText(self.cfg.password)
        self._to.setText(self.cfg.to_addr); self._tls.setChecked(self.cfg.use_tls); self._ssl.setChecked(self.cfg.use_ssl)

        form = QFormLayout()
        form.addRow("", self._enabled)
        form.addRow("Sunucu:", self._host)
        form.addRow("Port:", self._port)
        form.addRow("Kullanıcı:", self._user)
        form.addRow("Parola:", self._pass)
        form.addRow("Alıcı (To):", self._to)
        form.addRow("", self._tls)
        form.addRow("", self._ssl)

        # Yeni: Test Mail butonu
        self.btn_test = QPushButton("Test Mail Gönder")
        self.btn_test.clicked.connect(self._test_mail)

        btns = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        btns.accepted.connect(self._save); btns.rejected.connect(self.reject)

        layout = QVBoxLayout(); layout.addLayout(form); layout.addWidget(self.btn_test); layout.addWidget(btns); self.setLayout(layout)

    def _save(self):
        self.cfg = SmtpConfig(
            enabled=self._enabled.isChecked(),
            host=self._host.text().strip() or "smtp.gmail.com",
            port=int(self._port.value()),
            user=self._user.text().strip(),
            password=self._pass.text().strip(),
            to_addr=self._to.text().strip(),
            use_tls=self._tls.isChecked(),
            use_ssl=self._ssl.isChecked()
        )
        save_smtp(self.cfg)
        QMessageBox.information(self, "Kaydedildi", "SMTP ayarları kaydedildi.")
        self.accept()

    def _test_mail(self):
        # Kaydetmeden hızlı test
        temp_cfg = SmtpConfig(
            enabled=True,
            host=self._host.text().strip() or "smtp.gmail.com",
            port=int(self._port.value()),
            user=self._user.text().strip(),
            password=self._pass.text().strip(),
            to_addr=self._to.text().strip(),
            use_tls=self._tls.isChecked(),
            use_ssl=self._ssl.isChecked()
        )
        if not temp_cfg.user or not temp_cfg.password or not temp_cfg.to_addr:
            QMessageBox.warning(self, "Eksik", "Kullanıcı, Parola ve To alanlarını doldurun.")
            return
        try:
            msg = MIMEText("<h3>SMTP Test</h3><p>Bu bir test mailidir.</p>", "html", "utf-8")
            msg["Subject"] = "[BOT] SMTP Test"
            msg["From"] = temp_cfg.user
            msg["To"] = temp_cfg.to_addr
            if temp_cfg.use_ssl:
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(temp_cfg.host, temp_cfg.port, context=context, timeout=30) as s:
                    s.login(temp_cfg.user, temp_cfg.password)
                    s.send_message(msg)
            else:
                with smtplib.SMTP(temp_cfg.host, temp_cfg.port, timeout=30) as s:
                    s.ehlo()
                    if temp_cfg.use_tls: s.starttls()
                    s.login(temp_cfg.user, temp_cfg.password)
                    s.send_message(msg)
            QMessageBox.information(self, "OK", "Test maili gönderildi.")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Test gönderimi başarısız:\n{e}")

# ---------- Toplu URL Ekle Dialog ----------
class BulkUrlDialog(QDialog):
    """
    Her satır:  URL | dakika | grup
    Dakika ve grup opsiyoneldir. Ayırıcı olarak | veya ; veya TAB kabul edilir.
    Örnek:
      https://youtube.com/watch?v=xxx | 3 | Gündüz
      https://site.com/a
    """
    def __init__(self, parent: 'MainWindow'):
        super().__init__(parent)
        self.setWindowTitle("Toplu URL Ekle")
        self.text = QTextEdit()
        self.text.setPlaceholderText("Her satıra bir URL yazın.\nİsteğe bağlı: URL | dakika | grup")
        self.min_spin = QSpinBox(); self.min_spin.setRange(1, 180); self.min_spin.setValue(parent.settings.minutes)
        self.grp_in = QLineEdit(); self.grp_in.setPlaceholderText("Varsayılan grup (boş bırakılabilir)")

        form = QFormLayout()
        form.addRow("Varsayılan dakika:", self.min_spin)
        form.addRow("Varsayılan grup:", self.grp_in)
        form.addRow("Veri:", self.text)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setText("Ekle")
        btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)

        lay = QVBoxLayout(); lay.addLayout(form); lay.addWidget(btns); self.setLayout(lay)

    def parsed(self) -> List[Tuple[str,int,str]]:
        out = []
        default_m = int(self.min_spin.value())
        default_g = self.grp_in.text().strip()
        raw = self.text.toPlainText().splitlines()
        for line in raw:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            for sep in ["\t", ";"]:
                s = s.replace(sep, "|")
            parts = [p.strip() for p in s.split("|")]
            url = parts[0] if parts else ""
            if not url:
                continue
            mins = default_m
            group = default_g
            if len(parts) >= 2 and parts[1].isdigit():
                mins = int(parts[1])
            if len(parts) >= 3 and parts[2]:
                group = parts[2]
            out.append((url, mins, group))
        return out

# ---------- Settings Dialog ----------
class SettingsDialog(QDialog):
    def __init__(self, parent: QWidget, settings: Settings):
        super().__init__(parent)
        self.setWindowTitle("Ayarlar")
        self._s = settings

        # Genel
        self.sp_minutes = QSpinBox(); self.sp_minutes.setRange(1, 180); self.sp_minutes.setValue(settings.minutes)
        self.cb_minimize = QCheckBox("Kapatınca sistem tepsisine küçült"); self.cb_minimize.setChecked(settings.minimize_to_tray)
        self.cmb_layout = QComboBox(); self.cmb_layout.addItems(["Auto","2x2","1x2","1x1"])
        self.cmb_layout.setCurrentText(settings.window_layout or "Auto")

        # Tarayıcılar
        self.cb_chrome  = QCheckBox("Chrome"); self.cb_chrome.setChecked(settings.use_chrome)
        self.cb_firefox = QCheckBox("Firefox"); self.cb_firefox.setChecked(settings.use_firefox)
        self.cb_edge    = QCheckBox("Edge"); self.cb_edge.setChecked(settings.use_edge)
        self.cb_brave   = QCheckBox("Brave"); self.cb_brave.setChecked(settings.use_brave)
        self.cb_opera   = QCheckBox("Opera"); self.cb_opera.setChecked(settings.use_opera)

        self.ed_chrome  = QLineEdit(settings.chrome_binary);  self.btn_chrome  = QPushButton("Seç…")
        self.ed_firefox = QLineEdit(settings.firefox_binary); self.btn_firefox = QPushButton("Seç…")
        self.ed_edge    = QLineEdit(settings.edge_binary);    self.btn_edge    = QPushButton("Seç…")
        self.ed_brave   = QLineEdit(settings.brave_binary);   self.btn_brave   = QPushButton("Seç…")
        self.ed_opera   = QLineEdit(settings.opera_binary);   self.btn_opera   = QPushButton("Seç…")

        def pick_path(target: QLineEdit, title: str):
            path, _ = QFileDialog.getOpenFileName(self, title, os.path.expanduser("~"), "Uygulama (*.exe);;Tümü (*)")
            if path: target.setText(path)

        self.btn_chrome.clicked.connect(lambda: pick_path(self.ed_chrome, "Chrome uygulamasını seç"))
        self.btn_firefox.clicked.connect(lambda: pick_path(self.ed_firefox, "Firefox uygulamasını seç"))
        self.btn_edge.clicked.connect(lambda: pick_path(self.ed_edge, "Edge uygulamasını seç"))
        self.btn_brave.clicked.connect(lambda: pick_path(self.ed_brave, "Brave uygulamasını seç"))
        self.btn_opera.clicked.connect(lambda: pick_path(self.ed_opera, "Opera uygulamasını seç"))

        # UA
        self.cmb_ua_mode = QComboBox(); self.cmb_ua_mode.addItems(["Auto","Manual"]); self.cmb_ua_mode.setCurrentText(settings.ua_mode or "Auto")
        self.ed_user_agent = QLineEdit(settings.user_agent)

        # Proxy
        self.cb_proxylist = QCheckBox("Proxy listesi (proxy.json / uzak) aktif"); self.cb_proxylist.setChecked(settings.proxy_enabled)
        self.sp_failover = QSpinBox(); self.sp_failover.setRange(10, 600); self.sp_failover.setValue(int(settings.proxy_failover_secs or 120))
        self.ed_http_proxy = QLineEdit(settings.http_proxy); self.ed_http_proxy.setPlaceholderText("http://host:port veya socks5://host:port veya socks4://host:port (tek-satır)")

        # YENİ: Proxy kaynağı ve tipi
        self.cmb_proxy_source = QComboBox()
        self.cmb_proxy_source.addItems(["Manual", "Optional", "GH1", "GH2", "GH3"])
        self.cmb_proxy_source.setCurrentText(settings.proxy_source_mode or "Manual")

        self.cmb_proxy_type = QComboBox()
        self.cmb_proxy_type.addItems(["HTTP", "SOCKS4", "SOCKS5"])
        self.cmb_proxy_type.setCurrentText(settings.proxy_type or "HTTP")

        self.ed_proxy_optional = QLineEdit(settings.proxy_optional_url)
        self.ed_proxy_optional.setPlaceholderText("Opsiyonel uzak kaynak URL (satır başına ip:port)")

        # VPN
        self.cb_vpn_rotate = QCheckBox("OpenVPN .ovpn rotasyonunu kullan")
        self.cb_vpn_rotate.setChecked(settings.vpn_rotate_enabled)

        self.ed_openvpn = QLineEdit(settings.openvpn_exe); self.btn_openvpn = QPushButton("Seç…")
        self.btn_openvpn.clicked.connect(lambda: pick_path(self.ed_openvpn, "openvpn.exe seç"))

        self.ed_ovpn_dir = QLineEdit(settings.vpn_ovpn_dir); self.btn_ovpn_dir = QPushButton("Klasör…")
        def pick_dir(target: QLineEdit, title: str):
            d = QFileDialog.getExistingDirectory(self, title, os.path.expanduser("~"))
            if d: target.setText(d)
        self.btn_ovpn_dir.clicked.connect(lambda: pick_dir(self.ed_ovpn_dir, "OVPN klasörü seç"))

        self.ed_vpn_user = QLineEdit(settings.vpn_username)
        self.ed_vpn_pass = QLineEdit(settings.vpn_password); self.ed_vpn_pass.setEchoMode(QLineEdit.Password)

        self.sp_vpn_cto = QSpinBox(); self.sp_vpn_cto.setRange(10, 300); self.sp_vpn_cto.setValue(settings.vpn_connect_timeout_sec)
        self.sp_vpn_sto = QSpinBox(); self.sp_vpn_sto.setRange(3, 120); self.sp_vpn_sto.setValue(settings.vpn_stop_timeout_sec)

        # Form
        form = QFormLayout()
        form.addRow("Her URL süresi (dk):", self.sp_minutes)
        form.addRow("Pencere yerleşimi:", self.cmb_layout)
        form.addRow("", self.cb_minimize)

        # Browser grid
        bgrid = QVBoxLayout()
        for cb, ed, btn, name in [
            (self.cb_chrome,  self.ed_chrome,  self.btn_chrome,  "Chrome"),
            (self.cb_firefox, self.ed_firefox, self.btn_firefox, "Firefox"),
            (self.cb_edge,    self.ed_edge,    self.btn_edge,    "Edge"),
            (self.cb_brave,   self.ed_brave,   self.btn_brave,   "Brave"),
            (self.cb_opera,   self.ed_opera,   self.btn_opera,   "Opera"),
        ]:
            row = QHBoxLayout(); row.addWidget(cb); row.addWidget(ed); row.addWidget(btn); bgrid.addLayout(row)
        form.addRow("Tarayıcılar:", QWidget()); form.itemAt(form.rowCount()-1, QFormLayout.FieldRole).widget().setLayout(bgrid)

        form.addRow("UA modu:", self.cmb_ua_mode)
        form.addRow("User-Agent (manuel):", self.ed_user_agent)

        form.addRow("", self.cb_proxylist)
        form.addRow("Proxy failover (sn):", self.sp_failover)
        form.addRow("Tek proxy:", self.ed_http_proxy)
        form.addRow("Proxy Kaynağı:", self.cmb_proxy_source)
        form.addRow("Proxy Tipi:", self.cmb_proxy_type)
        form.addRow("Opsiyonel Kaynak URL:", self.ed_proxy_optional)

        # VPN (OpenVPN rotasyonu)
        form.addRow("", self.cb_vpn_rotate)
        row_ovpn = QHBoxLayout(); row_ovpn.addWidget(self.ed_openvpn); row_ovpn.addWidget(self.btn_openvpn)
        form.addRow("openvpn.exe:", QWidget()); form.itemAt(form.rowCount()-1, QFormLayout.FieldRole).widget().setLayout(row_ovpn)
        row_dir = QHBoxLayout(); row_dir.addWidget(self.ed_ovpn_dir); row_dir.addWidget(self.btn_ovpn_dir)
        form.addRow("OVPN klasörü:", QWidget()); form.itemAt(form.rowCount()-1, QFormLayout.FieldRole).widget().setLayout(row_dir)
        form.addRow("VPN kullanıcı adı:", self.ed_vpn_user)
        form.addRow("VPN parola:", self.ed_vpn_pass)
        form.addRow("Bağlantı timeout (sn):", self.sp_vpn_cto)
        form.addRow("Kapatma timeout (sn):", self.sp_vpn_sto)

        btns = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)

        lay = QVBoxLayout(self); lay.addLayout(form); lay.addWidget(btns)

    def value(self) -> Settings:
        s = Settings(
            minutes=int(self.sp_minutes.value()),
            use_chrome=self.cb_chrome.isChecked(),
            use_firefox=self.cb_firefox.isChecked(),
            use_edge=self.cb_edge.isChecked(),
            use_brave=self.cb_brave.isChecked(),
            use_opera=self.cb_opera.isChecked(),
            chrome_binary=self.ed_chrome.text().strip(),
            firefox_binary=self.ed_firefox.text().strip(),
            edge_binary=self.ed_edge.text().strip(),
            brave_binary=self.ed_brave.text().strip(),
            opera_binary=self.ed_opera.text().strip(),
            ua_mode=self.cmb_ua_mode.currentText(),
            user_agent=self.ed_user_agent.text().strip(),
            http_proxy=self.ed_http_proxy.text().strip(),
            proxy_enabled=self.cb_proxylist.isChecked(),
            proxy_failover_secs=int(self.sp_failover.value()),
            vpn_provider=VPNProvider.OPENVPN,  # bu panel OpenVPN rotasyonu için
            vpn_exe_path="",  # kullanılmıyor
            minimize_to_tray=self._s.minimize_to_tray,
            window_layout=self.cmb_layout.currentText(),

            proxy_source_mode=self.cmb_proxy_source.currentText(),
            proxy_type=self.cmb_proxy_type.currentText(),
            proxy_optional_url=self.ed_proxy_optional.text().strip(),

            vpn_rotate_enabled=self.cb_vpn_rotate.isChecked(),
            openvpn_exe=self.ed_openvpn.text().strip(),
            vpn_ovpn_dir=self.ed_ovpn_dir.text().strip(),
            vpn_username=self.ed_vpn_user.text().strip(),
            vpn_password=self.ed_vpn_pass.text().strip(),
            vpn_connect_timeout_sec=int(self.sp_vpn_cto.value()),
            vpn_stop_timeout_sec=int(self.sp_vpn_sto.value()),
        )
        return s

# ---------- Ana Pencere ----------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} — URL Yönlendirme (Gruplar, Zamanlama, Proxy, SMTP, OpenVPN)")
        if os.path.exists(APP_ICON):
            self.setWindowIcon(QIcon(APP_ICON))
        self.resize(1320, 820)

        self.settings, self.schedules = load_all()
        self.worker: Optional[RotatorWorker] = None
        self.scheduler = SchedulerThread(self); self.scheduler.start()
        self.queue: List[ScheduleItem] = []
        self.groups: List[str] = load_groups()
        self._paused = False

        # Üst menü: GENEL / GRUPLAR / URL LİSTESİ / PROXY / SMTP
        menubar = QMenuBar()
        m_general = menubar.addMenu("Genel")
        m_groups  = menubar.addMenu("Gruplar")
        m_urls    = menubar.addMenu("URL Listesi")
        m_proxy   = menubar.addMenu("Proxyler")
        m_smtp    = menubar.addMenu("SMTP")

        # Genel
        act_settings = m_general.addAction("Ayarlar…")
        act_start    = m_general.addAction("Başlat (Grup)")
        act_pause    = m_general.addAction("Çalışmayı duraklat / sürdür")
        act_stop     = m_general.addAction("Durdur")
        m_general.addSeparator()
        act_save     = m_general.addAction("Listeleri Kaydet…")
        act_load     = m_general.addAction("Listeleri Yükle…")
        m_general.addSeparator()
        act_sched    = m_general.addAction("Zamanlama…")
        m_general.addSeparator()
        act_minimize = m_general.addAction("Arka planda çalıştır (minimize)")
        act_quit     = m_general.addAction("Çıkış")

        # Gruplar
        act_groups = m_groups.addAction("Grupları Aç…")

        # URL Listesi
        act_bulk       = m_urls.addAction("Toplu URL Ekle…")
        act_save_urls  = m_urls.addAction("Listeyi urllist.json olarak Kaydet")
        act_load_urls  = m_urls.addAction("urllist.json’dan Yükle")

        # Proxy
        act_proxy = m_proxy.addAction("Proxy Listesi…")

        # SMTP
        act_smtp = m_smtp.addAction("SMTP Ayarları…")

        self.setMenuBar(menubar)

        # Toolbar
        tb = QToolBar()
        btn_settings = QPushButton("Ayarlar"); btn_start = QPushButton("Başlat (Grup)")
        btn_pause = QPushButton("Duraklat/Sürdür"); btn_stop = QPushButton("Durdur")
        btn_save = QPushButton("Kaydet"); btn_load = QPushButton("Yükle"); btn_sched = QPushButton("Zamanlama")
        for b in (btn_settings, btn_start, btn_pause, btn_stop, btn_save, btn_load, btn_sched):
            tb.addWidget(b)
        self.addToolBar(tb)

        # Merkez
        central = QWidget(); root = QVBoxLayout(central)
        top = QHBoxLayout()
        self.status_lbl = QLabel("Hazır.")
        self.progress = QProgressBar(); self.progress.setRange(0, 100); self.progress.setValue(0); self.progress.setTextVisible(True)
        top.addWidget(self.status_lbl, 3); top.addWidget(self.progress, 2)
        top.addWidget(QLabel("Aktif Grup:"))
        self.cmb_active_group = QLineEdit(); self.cmb_active_group.setPlaceholderText("Örn. Gündüz")
        top.addWidget(self.cmb_active_group)
        root.addLayout(top)

        lists = QHBoxLayout(); self.left_list = QListWidget(); self.right_list = QListWidget()
        self.left_list.setSelectionMode(QListWidget.ExtendedSelection); self.right_list.setSelectionMode(QListWidget.ExtendedSelection)
        lists.addWidget(self.left_list, 1); lists.addWidget(self.right_list, 1)

        left_bar = QHBoxLayout()
        self.in_url = QLineEdit(); self.in_url.setPlaceholderText("URL ekle…")
        self.in_min = QSpinBox(); self.in_min.setRange(1, 180); self.in_min.setValue(self.settings.minutes)
        self.in_min.setMinimumWidth(60); self.in_min.setAlignment(Qt.AlignCenter)
        self.in_min.setStyleSheet("QSpinBox{color:#ededed; background:#2b2b2b;} QSpinBox:disabled{color:#777;} QSpinBox::up-button, QSpinBox::down-button{width:16px;}")
        self.in_group = QLineEdit(); self.in_group.setPlaceholderText("Grup (örn. Gündüz)")
        lbl_min = QLabel("dk")
        btn_add = QPushButton("Ekle"); btn_del = QPushButton("Sil")
        left_bar.addWidget(self.in_url); left_bar.addWidget(self.in_min); left_bar.addWidget(lbl_min); left_bar.addWidget(self.in_group); left_bar.addWidget(btn_add); left_bar.addWidget(btn_del)

        self.log = QTextEdit(); self.log.setReadOnly(True); self.log.setMinimumHeight(140)
        right_bar = QHBoxLayout(); btn_move_back = QPushButton("Seçileni Sola Al"); btn_clear_right = QPushButton("Sağı Temizle")
        right_bar.addWidget(btn_move_back); right_bar.addWidget(btn_clear_right)

        root.addLayout(lists); root.addLayout(left_bar); root.addLayout(right_bar); root.addWidget(self.log)
        self.setCentralWidget(central)

        # Tepsi
        self.tray = QSystemTrayIcon(self)
        if os.path.exists(APP_ICON):
            self.tray.setIcon(QIcon(APP_ICON))
        self.tray.setToolTip(APP_NAME)
        tray_menu = QMenu()
        act_show = QAction("Göster", self); act_show.triggered.connect(self.show_normal_from_tray)
        act_tray_exit = QAction("Çıkış", self); act_tray_exit.triggered.connect(self.exit_app)
        tray_menu.addAction(act_show); tray_menu.addAction(act_tray_exit)
        self.tray.setContextMenu(tray_menu); self.tray.show()

        # Sinyaller
        act_settings.triggered.connect(self.open_settings)
        act_start.triggered.connect(lambda: self.start_group_now(self.cmb_active_group.text().strip()))
        act_pause.triggered.connect(self.toggle_pause); act_stop.triggered.connect(self.stop_run)
        act_save.triggered.connect(self.save_lists); act_load.triggered.connect(self.load_lists); act_sched.triggered.connect(self.open_scheduler)
        act_minimize.triggered.connect(self.minimize_to_tray_now)
        act_quit.triggered.connect(self.exit_app)
        act_groups.triggered.connect(self.open_groups)
        act_proxy.triggered.connect(self.open_proxies)
        act_smtp.triggered.connect(self.open_smtp)

        act_bulk.triggered.connect(self.open_bulk_add)
        act_save_urls.triggered.connect(lambda: (save_url_list_from_widget(self.left_list), log_append(self.log, "URL listesi urllist.json’a kaydedildi.")))
        act_load_urls.triggered.connect(self.load_urls_from_file)

        btn_settings.clicked.connect(self.open_settings); btn_start.clicked.connect(lambda: self.start_group_now(self.cmb_active_group.text().strip()))
        btn_pause.clicked.connect(self.toggle_pause); btn_stop.clicked.connect(self.stop_run)
        btn_save.clicked.connect(self.save_lists); btn_load.clicked.connect(self.load_lists); btn_sched.clicked.connect(self.open_scheduler)
        btn_add.clicked.connect(self.add_url); btn_del.clicked.connect(self.delete_url); btn_move_back.clicked.connect(self.move_right_to_left); btn_clear_right.clicked.connect(self.right_list.clear)
        self.in_url.returnPressed.connect(self.add_url)

        self.refresh_group_completer()
        load_url_list_to_widget(self.left_list, self._make_item)

        self._notify(f"{APP_NAME} hazır.")
        save_groups(self.groups)

    def refresh_group_completer(self):
        others = [g for g in self.groups if g not in DEFAULT_GROUPS]
        groups_sorted = DEFAULT_GROUPS + sorted(others)
        self.groups = groups_sorted
        comp = QCompleter(groups_sorted); comp.setCaseSensitivity(Qt.CaseInsensitive)
        self.in_group.setCompleter(comp); self.cmb_active_group.setCompleter(QCompleter(groups_sorted))

    # ---- Tepsi / Kapatma ----
    def _notify(self, msg: str):
        if self.tray.isVisible():
            self.tray.showMessage(APP_NAME, msg, QSystemTrayIcon.Information, 3000)

    def closeEvent(self, event):
        if self.settings.minimize_to_tray:
            event.ignore()
            self.hide()
            self._notify("Arka planda çalışıyor.")
        else:
            try: self.scheduler.stop()
            except Exception: pass
            super().closeEvent(event)

    def minimize_to_tray_now(self):
        self.settings.minimize_to_tray = True
        save_all(self.settings, self.schedules)
        self.hide()
        self._notify("Arka planda çalışıyor.")

    def show_normal_from_tray(self):
        self.showNormal(); self.activateWindow()

    def exit_app(self):
        try:
            if self.worker: self.worker.stop()
        except Exception: pass
        try:
            self.scheduler.stop()
        except Exception: pass
        try:
            if hasattr(self.log, "_log_buf") and self.log._log_buf:
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write("\n".join(self.log._log_buf) + "\n")
                self.log._log_buf.clear()
        except Exception:
            pass
        self.tray.hide()
        QApplication.quit()

    # ---- Grup & URL ----
    def _make_item(self, url: str, mins: int, group: str) -> QListWidgetItem:
        label = f"{url}  [{mins} dk]  {{{group or '—'}}}"
        itm = QListWidgetItem(label); itm.setData(Qt.UserRole, (url, int(mins))); itm.setData(Qt.UserRole+1, group or ""); return itm

    def add_url(self):
        url = self.in_url.text().strip(); mins = int(self.in_min.value()); group = self.in_group.text().strip()
        if url:
            self.left_list.addItem(self._make_item(url, mins, group)); self.in_url.clear()
            if group and group not in self.groups:
                self.groups.append(group); save_groups(self.groups); self.refresh_group_completer()
            save_url_list_from_widget(self.left_list)

    def delete_url(self):
        for item in self.left_list.selectedItems(): self.left_list.takeItem(self.left_list.row(item))
        save_url_list_from_widget(self.left_list)

    def move_right_to_left(self):
        for item in self.right_list.selectedItems():
            data = item.data(Qt.UserRole) or (item.text(), self.settings.minutes); grp = item.data(Qt.UserRole+1) or ""
            self.left_list.addItem(self._make_item(data[0], int(data[1]), grp)); self.right_list.takeItem(self.right_list.row(item))
        save_url_list_from_widget(self.left_list)

    # ---- Ayarlar / Proxy / SMTP / Toplu ekleme ----
    def open_settings(self):
        dlg = SettingsDialog(self, self.settings)
        if dlg.exec() == QDialog.Accepted:
            self.settings = dlg.value(); save_all(self.settings, self.schedules)
            vpn_info = "ON" if self.settings.vpn_rotate_enabled else "OFF"
            self.status_lbl.setText(
                f"Ayarlandı: {self.settings.minutes} dk | Chrome={self.settings.use_chrome} Firefox={self.settings.use_firefox} Edge={self.settings.use_edge} Brave={self.settings.use_brave} Opera={self.settings.use_opera} | Yerleşim={self.settings.window_layout} | ProxyAktif={self.settings.proxy_enabled} | VPN-Rotate={vpn_info}"
            )

    def open_groups(self):
        dlg = GroupsDialog(self); dlg.exec()

    def open_proxies(self):
        dlg = ProxyDialog(self); dlg.exec()
        pcount = len(load_proxies())
        log_append(self.log, f"Proxy listesi güncellendi. Toplam {pcount} adet.")

    def open_smtp(self):
        dlg = SmtpDialog(self); dlg.exec()

    def open_bulk_add(self):
        dlg = BulkUrlDialog(self)
        if dlg.exec() == QDialog.Accepted:
            rows = dlg.parsed()
            for (u, m, g) in rows:
                self.left_list.addItem(self._make_item(u, int(m), g))
                if g and g not in self.groups:
                    self.groups.append(g)
            if rows:
                save_groups(self.groups); self.refresh_group_completer()
                save_url_list_from_widget(self.left_list)
            log_append(self.log, f"Toplu ekleme tamamlandı. {len(rows)} satır işlendi.")

    def load_urls_from_file(self):
        count = load_url_list_to_widget(self.left_list, self._make_item)
        if count > 0:
            log_append(self.log, f"urllist.json yüklendi. {count} kayıt.")
        else:
            log_append(self.log, "urllist.json bulunamadı veya boş.")

    # ---- Çalıştırma ----
    def _collect_left_group(self, group: str) -> List[Tuple[str,int]]:
        out: List[Tuple[str,int]] = []
        for i in range(self.left_list.count()):
            item = self.left_list.item(i); ig = (item.data(Qt.UserRole+1) or "").strip()
            if (group == "" or ig == group):
                data = item.data(Qt.UserRole) or (item.text(), self.settings.minutes)
                out.append((data[0], int(data[1])))
        return out

    def start_group_now(self, group: str,
        override_browsers: Tuple[Optional[bool],Optional[bool],Optional[bool],Optional[bool],Optional[bool]] = (None,None,None,None,None)):
        group = (group or "").strip()
        if self.worker:
            QMessageBox.warning(self, "Uyarı", "Zaten çalışıyor."); return
        urls_with_minutes = self._collect_left_group(group)
        if not urls_with_minutes:
            QMessageBox.information(self, "Bilgi", f"Seçili grupta URL yok: {group or 'Hepsi'}"); return
        uc, uf, ue, ub, uo = override_browsers
        if any(v is not None for v in (uc,uf,ue,ub,uo)):
            if uc is not None: self.settings.use_chrome = uc
            if uf is not None: self.settings.use_firefox = uf
            if ue is not None: self.settings.use_edge = ue
            if ub is not None: self.settings.use_brave = ub
            if uo is not None: self.settings.use_opera = uo
            save_all(self.settings, self.schedules)

        screen = QApplication.primaryScreen().availableGeometry(); screen_rect = (screen.x(), screen.y(), screen.width(), screen.height())
        self.signals = WorkerSignals()
        self.signals.moved.connect(self.on_moved)
        self.signals.finished.connect(self.on_finished)
        self.signals.status.connect(self.on_status)
        self.signals.progress.connect(self.on_progress)

        self.worker = RotatorWorker(urls_with_minutes, self.settings, self.signals, screen_rect)
        self.worker.start(); self.status_lbl.setText(f"Çalışıyor… (Grup: {group or 'Hepsi'})"); self.progress.setValue(0)

    def toggle_pause(self):
        if not self.worker: return
        if self._paused:
            self.worker.pause(False); self._paused = False; self.status_lbl.setText("Sürdürülüyor…")
        else:
            self.worker.pause(True); self._paused = True; self.status_lbl.setText("Duraklatıldı.")

    def stop_run(self):
        if self.worker:
            self.worker.stop(); self.status_lbl.setText("Durduruluyor…")

    # ---- Listeleri Kaydet/Yükle ----
    def save_lists(self):
        path, _ = QFileDialog.getSaveFileName(self, "Listeleri Kaydet", os.path.expanduser("~"), "JSON (*.json)")
        if not path: return
        data = {
            "left": [(
                self.left_list.item(i).data(Qt.UserRole)[0],
                int(self.left_list.item(i).data(Qt.UserRole)[1]),
                self.left_list.item(i).data(Qt.UserRole+1) or ""
            ) for i in range(self.left_list.count())],
            "right": [(
                (self.right_list.item(i).data(Qt.UserRole) or (self.right_list.item(i).text(), self.settings.minutes))[0],
                int((self.right_list.item(i).data(Qt.UserRole) or (self.right_list.item(i).text(), self.settings.minutes))[1]),
                self.right_list.item(i).data(Qt.UserRole+1) or ""
            ) for i in range(self.right_list.count())]
        }
        try:
            with open(path, "w", encoding="utf-8") as f: json.dump(data, f, ensure_ascii=False, indent=2)
            self.status_lbl.setText(f"Kaydedildi: {path}"); log_append(self.log, f"Listeler kaydedildi: {path}")
            save_url_list_from_widget(self.left_list)
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Kaydedilemedi: {e}")

    def load_lists(self):
        path, _ = QFileDialog.getOpenFileName(self, "Listeleri Yükle", os.path.expanduser("~"), "JSON (*.json)")
        if not path: return
        try:
            with open(path, "r", encoding="utf-8") as f: data = json.load(f)
            self.left_list.clear(); self.right_list.clear()
            for (u, m, g) in data.get("left", []): self.left_list.addItem(self._make_item(u, int(m), g))
            for (u, m, g) in data.get("right", []): self.right_list.addItem(self._make_item(u, int(m), g))
            self.status_lbl.setText(f"Yüklendi: {path}"); log_append(self.log, f"Listeler yüklendi: {path}")
            save_url_list_from_widget(self.left_list)
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Yüklenemedi: {e}")

    # ---- Zamanlama ----
    def open_scheduler(self):
        dlg = ScheduleDialog(self); dlg.exec()

    def enqueue_job(self, sched: ScheduleItem):
        self.queue.append(sched); log_append(self.log, f"Kuyruğa alındı: {sched.group_name} @ {sched.time_hhmm}")
        self.try_start_next_job()

    def try_start_next_job(self):
        if self.worker is not None or not self.queue: return
        s = self.queue.pop(0); log_append(self.log, f"Başlıyor (kuyruktan): {s.group_name} @ {s.time_hhmm}")
        vpn_path = (s.vpn_exe_path or self.settings.vpn_exe_path or guess_vpn_exe(self.settings.vpn_provider)).strip()
        if vpn_path and os.path.exists(vpn_path):
            try:
                import subprocess
                subprocess.Popen([vpn_path], shell=False)
            except Exception:
                pass
        overrides = (s.use_chrome, s.use_firefox, s.use_edge, s.use_brave, s.use_opera)
        self.start_group_now(s.group_name, overrides)

    # Worker geri çağrıları
    def on_moved(self, url: str):
        for i in range(self.left_list.count()):
            item = self.left_list.item(i); data = item.data(Qt.UserRole)
            if isinstance(data, tuple) and len(data)==2 and data[0]==url:
                itm = self.left_list.takeItem(i); self.right_list.addItem(itm); break

    def on_finished(self):
        self.worker = None; self.status_lbl.setText("Tamamlandı veya durduruldu.")
        self.progress.setValue(0)
        log_append(self.log, "İş tamamlandı.")
        cfg = load_smtp()
        if cfg.enabled:
            log_append(self.log, f"SMTP: {cfg.to_addr} adresine bildirim denendi.")
        self.try_start_next_job()

    def on_status(self, msg: str):
        self.status_lbl.setText(msg); log_append(self.log, msg)

    def on_progress(self, elapsed: int, total: int, url: str):
        pct = int(max(0, min(100, (elapsed/total)*100)))
        mm_e, ss_e = divmod(elapsed, 60)
        mm_t, ss_t = divmod(total, 60)
        self.progress.setValue(pct)
        self.status_lbl.setText(f"{url} — {mm_e:02d}:{ss_e:02d} / {mm_t:02d}:{ss_t:02d}  ({pct}%)")

# ---------- Zamanlama Thread & Dialoglar ----------
class SchedulerThread(threading.Thread):
    def __init__(self, main_ref: 'MainWindow'):
        super().__init__(daemon=True)
        self.main = main_ref
        self._stop = threading.Event(); self._stop.clear()
        self._last_seen_min = None

    def run(self):
        while not self._stop.is_set():
            try:
                now = time.localtime()
                minute_key = (now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min)
                hhmm = f"{now.tm_hour:02d}:{now.tm_min:02d}"
                wday = (now.tm_wday)
                if minute_key != self._last_seen_min:
                    for s in list(self.main.schedules):
                        if not s.enabled: continue
                        if s.time_hhmm != hhmm: continue
                        if s.weekdays and wday not in s.weekdays: continue
                        self.main.enqueue_job(s)
                    self._last_seen_min = minute_key
                time.sleep(5)
            except Exception:
                time.sleep(5)

    def stop(self): self._stop.set()

class ScheduleItemDialog(QDialog):
    def __init__(self, parent: 'MainWindow', current: Optional[ScheduleItem]=None):
        super().__init__(parent)
        self.setWindowTitle("Zamanlı İş")
        self._time = QTimeEdit(); self._time.setDisplayFormat("HH:mm"); self._time.setTime(QTime.currentTime())
        self._group = QLineEdit(); self._group.setPlaceholderText("Grup adı (örn. Gündüz)")
        self._vpn_path = QLineEdit(); self._vpn_path.setPlaceholderText("(Opsiyonel) Bu işte açılacak VPN exe)")
        btn_browse = QPushButton("Gözat…"); btn_browse.clicked.connect(self._pick)
        self._enabled = QCheckBox("Etkin"); self._enabled.setChecked(True)
        self._days = QComboBox(); self._days.addItems(["Her Gün","Hafta İçi","Hafta Sonu"])
        self._cb_chrome = QCheckBox("Chrome"); self._cb_firefox = QCheckBox("Firefox"); self._cb_edge = QCheckBox("Edge"); self._cb_brave = QCheckBox("Brave"); self._cb_opera = QCheckBox("Opera")

        if current:
            hh, mm = map(int, current.time_hhmm.split(":")); self._time.setTime(QTime(hh, mm))
            self._group.setText(current.group_name)
            self._vpn_path.setText(current.vpn_exe_path)
            self._enabled.setChecked(current.enabled)
            if current.weekdays:
                wd = set(current.weekdays)
                self._days.setCurrentText("Hafta İçi" if wd == set(range(0,5)) else ("Hafta Sonu" if wd == {5,6} else "Her Gün"))
            for cb, val in (
                (self._cb_chrome, current.use_chrome),
                (self._cb_firefox, current.use_firefox),
                (self._cb_edge, current.use_edge),
                (self._cb_brave, current.use_brave),
                (self._cb_opera, current.use_opera),
            ):
                if val is not None: cb.setChecked(bool(val))

        form = QFormLayout()
        form.addRow("Saat (HH:MM):", self._time); form.addRow("Grup:", self._group)
        row = QHBoxLayout(); row.addWidget(self._vpn_path); row.addWidget(btn_browse); form.addRow("VPN Programı:", QWidget()); form.itemAt(form.rowCount()-1, QFormLayout.FieldRole).widget().setLayout(row)
        form.addRow("Günler:", self._days)
        rowb = QHBoxLayout()
        for x in (self._cb_chrome,self._cb_firefox,self._cb_edge,self._cb_brave,self._cb_opera): rowb.addWidget(x)
        form.addRow("Tarayıcılar (opsiyonel):", QWidget()); form.itemAt(form.rowCount()-1, QFormLayout.FieldRole).widget().setLayout(rowb)
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel); btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)
        layout = QVBoxLayout(); layout.addLayout(form); layout.addWidget(self._enabled); layout.addWidget(btns); self.setLayout(layout)

    def _pick(self):
        path, _ = QFileDialog.getOpenFileName(self, "VPN Uygulaması Seç (exe)", os.path.expanduser("~"), "Program (*.exe)")
        if path: self._vpn_path.setText(path)

    def _weekdays(self) -> List[int]:
        k = self._days.currentText()
        if k == "Hafta İçi": return list(range(0,5))
        if k == "Hafta Sonu": return [5,6]
        return []

    def value(self) -> ScheduleItem:
        t = self._time.time(); hhmm = f"{t.hour():02d}:{t.minute():02d}"
        vals = dict(
            time_hhmm=hhmm, group_name=self._group.text().strip(), vpn_exe_path=self._vpn_path.text().strip(), enabled=self._enabled.isChecked(), weekdays=self._weekdays(),
            use_chrome=self._cb_chrome.isChecked() if self._cb_chrome.isChecked() else None,
            use_firefox=self._cb_firefox.isChecked() if self._cb_firefox.isChecked() else None,
            use_edge=self._cb_edge.isChecked() if self._cb_edge.isChecked() else None,
            use_brave=self._cb_brave.isChecked() if self._cb_brave.isChecked() else None,
            use_opera=self._cb_opera.isChecked() if self._cb_opera.isChecked() else None,
        )
        return ScheduleItem(**vals)

class ScheduleDialog(QDialog):
    def __init__(self, parent: 'MainWindow'):
        super().__init__(parent)
        self.setWindowTitle("Zamanlama")
        self.parent_ref = parent
        self._list = QListWidget(); self._btn_add = QPushButton("Ekle"); self._btn_edit = QPushButton("Düzenle"); self._btn_del = QPushButton("Sil"); self._btn_toggle = QPushButton("Etkin/Pasif")
        self._reload()
        btns = QHBoxLayout(); [btns.addWidget(b) for b in (self._btn_add,self._btn_edit,self._btn_del,self._btn_toggle)]
        layout = QVBoxLayout(); layout.addWidget(self._list); layout.addLayout(btns)
        close_box = QDialogButtonBox(QDialogButtonBox.Close); close_box.rejected.connect(self.reject); close_box.accepted.connect(self.accept)
        layout.addWidget(close_box); self.setLayout(layout)
        self._btn_add.clicked.connect(self._add); self._btn_edit.clicked.connect(self._edit); self._btn_del.clicked.connect(self._delete); self._btn_toggle.clicked.connect(self._toggle)

    def _reload(self):
        self._list.clear()
        for s in self.parent_ref.schedules:
            flag = "(Açık)" if s.enabled else "(Kapalı)"
            days = "Her Gün" if not s.weekdays else ("Hafta İçi" if set(s.weekdays)==set(range(0,5)) else ("Hafta Sonu" if set(s.weekdays)=={5,6} else ",".join(map(str,s.weekdays))))
            vpn = os.path.basename(s.vpn_exe_path) if s.vpn_exe_path else "(Ayarlar’daki)"
            brs = ", ".join([n for n,v in (('Ch',s.use_chrome),('Fx',s.use_firefox),('Ed',s.use_edge),('Br',s.use_brave),('Op',s.use_opera)) if v]) or "(Global)"
            self._list.addItem(f"{s.time_hhmm}  —  {days} — Grup: {s.group_name} — VPN: {vpn} — Tarayıcı: {brs}  {flag}")

    def _select_index(self) -> int:
        row = self._list.currentRow(); return row if 0 <= row < len(self.parent_ref.schedules) else -1

    def _add(self):
        dlg = ScheduleItemDialog(self.parent_ref)
        if dlg.exec() == QDialog.Accepted:
            self.parent_ref.schedules.append(dlg.value()); save_all(self.parent_ref.settings, self.parent_ref.schedules); self._reload()

    def _edit(self):
        idx = self._select_index();
        if idx < 0: return
        dlg = ScheduleItemDialog(self.parent_ref, self.parent_ref.schedules[idx])
        if dlg.exec() == QDialog.Accepted:
            self.parent_ref.schedules[idx] = dlg.value(); save_all(self.parent_ref.settings, self.parent_ref.schedules); self._reload()

    def _delete(self):
        idx = self._select_index();
        if idx < 0: return
        self.parent_ref.schedules.pop(idx); save_all(self.parent_ref.settings, self.parent_ref.schedules); self._reload()

    def _toggle(self):
        idx = self._select_index();
        if idx < 0: return
        self.parent_ref.schedules[idx].enabled = not self.parent_ref.schedules[idx].enabled
        save_all(self.parent_ref.settings, self.parent_ref.schedules); self._reload()

if __name__ == "__main__":
    try:
        import psutil
        p = psutil.Process(os.getpid())
        p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
    except Exception:
        pass

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    w = MainWindow()
    if os.path.exists(APP_ICON):
        w.setWindowIcon(QIcon(APP_ICON))
    w.show()
    sys.exit(app.exec())
