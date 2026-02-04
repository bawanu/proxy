import socket
import threading
import select
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, Menu
import base64
import json
import time
import os
import sys
import struct
import datetime
import ctypes 

# --- 1. HIGH DPI FIX ---
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except: pass

# --- DEPENDENCY CHECK ---
try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:
    pystray = None

# --- THEME CONFIGURATION ---
COLORS = {
    "bg_void": "#050505",       
    "bg_panel": "#0f111a",      
    "neon_cyan": "#00f3ff",     
    "neon_cyan_dim": "#005f63", 
    "neon_purple": "#bd00ff",   
    "neon_purple_dim": "#4a0063",
    "danger": "#ff003c",        
    "danger_dim": "#590015",
    "success": "#00ff41",
    "text_main": "#e0e0e0",
    "text_dim": "#666666",
    "grid_line": "#1a1a1a"
}

FONT_HEADER = ("Orbitron", 14, "bold") 
FONT_MONO = ("Consolas", 9)
FONT_UI = ("Segoe UI", 10)

# --- CONFIG MANAGER ---
class ConfigManager:
    def __init__(self, filename="bavo_proxy.json"):
        self.filename = filename
        self.defaults = {
            "host": "0.0.0.0",
            "port": 8888,
            "auth_enabled": False,
            "username": "admin",
            "password": "password",
            "whitelist_enabled": False,
            "whitelist_ips": "127.0.0.1",
            "blacklist_domains": "doubleclick.net, ads.google.com",
            "speed_limit_kbps": 0,
            "max_conns_per_ip": 50,
            "users": {}  
        }
        self.config = self.load()

    def load(self):
        if not os.path.exists(self.filename): return self.defaults.copy()
        try:
            with open(self.filename, 'r') as f: return {**self.defaults, **json.load(f)}
        except: return self.defaults.copy()

    def save(self, config_dict):
        self.config = config_dict
        try:
            with open(self.filename, 'w') as f: json.dump(self.config, f, indent=4)
        except Exception as e: print(f"Save Error: {e}")

# --- PROXY ENGINE ---
class ProxyEngine:
    def __init__(self, config, log_func, stats_func, conn_func, user_update_func):
        self.config = config
        self.log = log_func
        self.update_stats = stats_func
        self.update_conns = conn_func
        self.update_user_info = user_update_func
        self.server_socket = None
        self.running = False
        
        self.active_connections = {} 
        self.client_sockets = set()
        self.ip_connection_counts = {}
        
        self.total_upload = 0
        self.total_download = 0
        self.lock = threading.Lock()
        self.refresh_config(config)

    def refresh_config(self, new_config=None):
        if new_config: self.config = new_config
        self.global_blacklist = [d.strip().encode() for d in self.config.get("blacklist_domains", "").split(',') if d.strip()]

    def flush_connections(self, target_ip=None):
        killed = 0
        with self.lock:
            for sock in list(self.client_sockets):
                try:
                    try: r_ip = sock.getpeername()[0]
                    except: r_ip = None
                    if target_ip and r_ip != target_ip: continue
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                    self.client_sockets.remove(sock)
                    killed += 1
                except: pass
            
            if target_ip:
                keys_to_del = [k for k,v in self.active_connections.items() if v['src'][0] == target_ip]
                for k in keys_to_del: del self.active_connections[k]
            else:
                self.active_connections.clear()
            
            self.update_conns(self.active_connections.copy())
        return killed

    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config["host"], int(self.config["port"])))
            self.server_socket.listen(100)
            self.running = True
            self.log(f"[CORE] SYSTEM INITIALIZED ON PORT {self.config['port']}")
            threading.Thread(target=self._accept_loop, daemon=True).start()
        except Exception as e:
            self.log(f"[CRITICAL] CORE FAILURE: {e}")
            self.running = False

    def stop(self):
        self.running = False
        self.flush_connections()
        if self.server_socket:
            try: self.server_socket.close()
            except: pass
        self.log("[CORE] SYSTEM SHUTDOWN SEQUENCE COMPLETE.")

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                src_ip = client_addr[0]

                if self.config["whitelist_enabled"]:
                    if src_ip not in [ip.strip() for ip in self.config["whitelist_ips"].split(',')]:
                        client_sock.close()
                        continue
                
                user_config = self.config["users"].get(src_ip, {})
                if user_config.get("banned", False):
                    client_sock.close()
                    continue

                curr_count = self.ip_connection_counts.get(src_ip, 0)
                max_allowed = int(self.config.get("max_conns_per_ip", 50))
                if curr_count >= max_allowed:
                    client_sock.close()
                    continue
                
                self.ip_connection_counts[src_ip] = curr_count + 1
                threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True).start()
            except: break

    def _detect_os(self, request_bytes):
        try:
            req_str = request_bytes.decode('utf-8', 'ignore').lower()
            agent_line = next((line for line in req_str.split('\r\n') if line.startswith('user-agent:')), "")
            if "windows" in agent_line: return "Windows PC"
            if "android" in agent_line: return "Android Mobile"
            if "iphone" in agent_line or "ipad" in agent_line: return "Apple iOS"
            if "macintosh" in agent_line: return "Mac OS"
            if "linux" in agent_line: return "Linux System"
            return "Unknown/App"
        except: return "Unknown"

    def _handle_client(self, client_sock, client_addr):
        conn_id = f"{client_addr[0]}:{client_addr[1]}"
        src_ip = client_addr[0]
        start_ts = time.time()
        
        with self.lock:
            self.client_sockets.add(client_sock)

        try:
            first_byte = client_sock.recv(1, socket.MSG_PEEK)
            if not first_byte: return

            if first_byte == b'\x05':
                self._handle_socks5(client_sock, client_addr, conn_id, src_ip, start_ts)
            else:
                self._handle_http(client_sock, client_addr, conn_id, src_ip, start_ts)

        except Exception:
            pass
        finally:
             with self.lock:
                if client_sock in self.client_sockets:
                    self.client_sockets.remove(client_sock)
                if conn_id in self.active_connections:
                    del self.active_connections[conn_id]
                    self.update_conns(self.active_connections.copy())
             
             cur = self.ip_connection_counts.get(src_ip, 1)
             if cur > 0: self.ip_connection_counts[src_ip] = cur - 1
             
             try: client_sock.close() 
             except: pass

    def _handle_socks5(self, client_sock, client_addr, conn_id, src_ip, start_ts):
        try:
            header = client_sock.recv(2)
            if not header or len(header) < 2: return
            ver, nmethods = struct.unpack("!BB", header)
            client_sock.recv(nmethods)

            if self.config["auth_enabled"]:
                client_sock.sendall(struct.pack("!BB", 0x05, 0x02))
                try:
                    auth_ver = client_sock.recv(1)
                    if not auth_ver: return 
                    ulen = ord(client_sock.recv(1))
                    username = client_sock.recv(ulen).decode()
                    plen = ord(client_sock.recv(1))
                    password = client_sock.recv(plen).decode()
                    if username == self.config["username"] and password == self.config["password"]:
                        client_sock.sendall(struct.pack("!BB", 0x01, 0x00))
                    else:
                        client_sock.sendall(struct.pack("!BB", 0x01, 0x01))
                        return 
                except: return 
            else:
                client_sock.sendall(struct.pack("!BB", 0x05, 0x00))

            req = client_sock.recv(4)
            if len(req) < 4: return
            ver, cmd, rsv, atyp = struct.unpack("!BBBB", req)

            target_host = ""
            if atyp == 1: 
                target_host = socket.inet_ntoa(client_sock.recv(4))
            elif atyp == 3: 
                l = ord(client_sock.recv(1))
                target_host = client_sock.recv(l).decode()
            elif atyp == 4: 
                target_host = socket.inet_ntop(socket.AF_INET6, client_sock.recv(16))
            else: return

            target_port = struct.unpack('!H', client_sock.recv(2))[0]

            user_config = self.config["users"].get(src_ip, {})
            speed_limit = int(user_config.get("limit", self.config.get("speed_limit_kbps", 0)))
            user_bl_str = user_config.get("blacklist", "")
            combined_blacklist = self.global_blacklist + [d.strip().encode() for d in user_bl_str.split(',') if d.strip()]
            
            for bad in combined_blacklist:
                if bad in target_host.encode():
                    self.log(f"[BLOCK] {target_host} FOR {src_ip}")
                    return

            if cmd == 1: 
                self._socks_tcp_connect(client_sock, target_host, target_port, speed_limit, conn_id, client_addr, start_ts)
            elif cmd == 3: 
                self._socks_udp_associate(client_sock, client_addr, src_ip)

        except Exception: pass

    def _socks_tcp_connect(self, client_sock, host, port, limit, conn_id, client_addr, start_ts):
        remote = None
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10)
            remote.connect((host, port))
            with self.lock: self.client_sockets.add(remote)

            reply = struct.pack("!BBBBIH", 0x05, 0x00, 0x00, 0x01, 0, 0)
            client_sock.sendall(reply)

            self.update_user_info(client_addr[0], "App/System (TCP)")
            with self.lock:
                self.active_connections[conn_id] = {"src": client_addr, "dst": f"{host}:{port}", "ts": start_ts}
                self.update_conns(self.active_connections.copy())
            
            self._tunnel(client_sock, remote, limit)
        except: pass
        finally:
            if remote:
                with self.lock: 
                    if remote in self.client_sockets: self.client_sockets.remove(remote)
                try: remote.close()
                except: pass

    def _socks_udp_associate(self, client_sock, client_addr, src_ip):
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind((self.config["host"], 0))
        _, udp_port = udp_sock.getsockname()

        ip_bytes = socket.inet_aton("0.0.0.0") 
        reply = struct.pack("!BBBB", 0x05, 0x00, 0x00, 0x01) + ip_bytes + struct.pack("!H", udp_port)
        client_sock.sendall(reply)
        
        self.update_user_info(src_ip, "App/VoIP (UDP)")
        threading.Thread(target=self._udp_relay_loop, args=(udp_sock, client_sock), daemon=True).start()
        
        while True:
            data = client_sock.recv(1024)
            if not data: break

    def _udp_relay_loop(self, udp_sock, tcp_ctrl_sock):
        udp_sock.settimeout(2)
        while True:
            try:
                if tcp_ctrl_sock.fileno() == -1: break
            except: break

            try:
                data, addr = udp_sock.recvfrom(65536)
                if len(data) < 10: continue
                atyp = data[3]
                header_len = 0
                dest_ip = ""
                dest_port = 0
                if atyp == 1: 
                    dest_ip = socket.inet_ntoa(data[4:8])
                    dest_port = struct.unpack("!H", data[8:10])[0]
                    header_len = 10
                elif atyp == 3:
                    l = data[4]
                    dest_ip = data[5:5+l].decode()
                    dest_port = struct.unpack("!H", data[5+l:7+l])[0]
                    header_len = 7+l
                
                payload = data[header_len:]
                fwd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                fwd_sock.sendto(payload, (dest_ip, dest_port))
                
                self.total_upload += len(payload)
                self.update_stats(0, len(payload))
            except socket.timeout: continue
            except: pass
        udp_sock.close()

    def _handle_http(self, client_sock, client_addr, conn_id, src_ip, start_ts):
        try:
            request = client_sock.recv(65536)
        except: return
        
        if not request: return

        device_info = self._detect_os(request)
        self.update_user_info(src_ip, device_info)
        
        if self.config["auth_enabled"] and not self._check_auth(request):
            client_sock.send(b'HTTP/1.1 407 Auth Required\r\nProxy-Authenticate: Basic realm="Access"\r\n\r\n')
            return

        first_line = request.split(b'\n')[0]
        try:
            method = first_line.split(b' ')[0]
            url_part = first_line.split(b' ')[1]
        except IndexError: return
        
        user_config = self.config["users"].get(src_ip, {})
        speed_limit = int(user_config.get("limit", self.config.get("speed_limit_kbps", 0)))
        user_bl_str = user_config.get("blacklist", "")
        combined_blacklist = self.global_blacklist + [d.strip().encode() for d in user_bl_str.split(',') if d.strip()]

        is_connect = (method == b"CONNECT")
        target_host = ""
        port = 80

        if is_connect:
            try:
                target_host = url_part.split(b":")[0].decode()
                port = int(url_part.split(b":")[1])
            except: pass
        else:
            http_pos = url_part.find(b"://")
            temp = url_part if http_pos == -1 else url_part[(http_pos + 3):]
            port_pos = temp.find(b":")
            path_pos = temp.find(b"/")
            if path_pos == -1: path_pos = len(temp)
            if port_pos == -1 or path_pos < port_pos: host_b = temp[:path_pos]
            else:
                host_b = temp[:port_pos]
                try: port = int(temp[port_pos+1:path_pos])
                except: pass
            target_host = host_b.decode()

        for bad in combined_blacklist:
            if bad in target_host.encode():
                self.log(f"[HTTP] BLOCKED: {target_host} FOR {src_ip}")
                client_sock.close()
                return

        with self.lock:
            self.active_connections[conn_id] = {"src": client_addr, "dst": f"{target_host}:{port}", "ts": start_ts}
            self.update_conns(self.active_connections.copy())

        remote_sock = None
        try:
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(10)
            remote_sock.connect((target_host, port))
            with self.lock: self.client_sockets.add(remote_sock)

            if is_connect:
                client_sock.send(b"HTTP/1.1 200 Connection established\r\n\r\n")
                self._tunnel(client_sock, remote_sock, speed_limit)
            else:
                remote_sock.send(request)
                self._tunnel(client_sock, remote_sock, speed_limit)
        except: pass
        finally:
            if remote_sock:
                with self.lock:
                    if remote_sock in self.client_sockets: self.client_sockets.remove(remote_sock)
                try: remote_sock.close()
                except: pass

    def _check_auth(self, req):
        headers = req.decode('utf-8', 'ignore').split('\r\n')
        auth = next((h for h in headers if h.lower().startswith('proxy-authorization: basic')), None)
        if not auth: return False
        try:
            creds = base64.b64decode(auth.split(' ')[2]).decode('utf-8')
            u, p = creds.split(':', 1)
            return u == self.config["username"] and p == self.config["password"]
        except: return False

    def _tunnel(self, client, remote, limit_kbps):
        sockets = [client, remote]
        chunk_size = 65536
        while True:
            try:
                readable, _, _ = select.select(sockets, [], [], 60)
            except ValueError: break
            if not readable: break
            try:
                for s in readable:
                    other = sockets[1] if s is sockets[0] else sockets[0]
                    data = s.recv(chunk_size)
                    if not data: return
                    other.sendall(data)
                    length = len(data)
                    if s is client:
                        self.total_upload += length
                        self.update_stats(0, length)
                    else:
                        self.total_download += length
                        self.update_stats(length, 0)
                    
                    if limit_kbps > 0:
                        bytes_per_sec = (limit_kbps * 1024) / 8
                        sleep_time = length / bytes_per_sec
                        time.sleep(sleep_time)
            except: break

# --- UI COMPONENTS ---
class CyberButton(tk.Canvas):
    def __init__(self, master, text, command, width=220, height=45):
        super().__init__(master, width=width, height=height, bg=COLORS["bg_panel"], highlightthickness=0)
        self.command = command
        self.is_active = False
        self.col_idle_base = COLORS["neon_cyan_dim"]
        self.col_idle_hover = COLORS["neon_cyan"]
        self.col_active_base = COLORS["danger_dim"]
        self.col_active_hover = COLORS["danger"]
        self.current_base = self.col_idle_base
        
        self.poly = self.create_polygon(
            15, 0, width, 0, width, height-15, width-15, height, 0, height, 0, 15,
            fill=self.col_idle_base, outline=""
        )
        self.text_id = self.create_text(width/2, height/2, text=text, fill=COLORS["bg_void"], font=("Segoe UI", 11, "bold"))
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<Button-1>", self.on_click)

    def set_state(self, active, text):
        self.is_active = active
        self.itemconfig(self.text_id, text=text)
        if active:
            self.current_base = self.col_active_base
            self.itemconfig(self.poly, fill=self.col_active_base)
            self.itemconfig(self.text_id, fill="white")
        else:
            self.current_base = self.col_idle_base
            self.itemconfig(self.poly, fill=self.col_idle_base)
            self.itemconfig(self.text_id, fill=COLORS["bg_void"])

    def on_enter(self, e):
        self.itemconfig(self.poly, fill=self.col_active_hover if self.is_active else self.col_idle_hover)
    def on_leave(self, e):
        self.itemconfig(self.poly, fill=self.current_base)
    def on_click(self, e):
        self.command()

class Oscilloscope(tk.Canvas):
    def __init__(self, master, color, width=400, height=120):
        super().__init__(master, width=width, height=height, bg=COLORS["bg_panel"], highlightthickness=0)
        self.color = color
        self.data = [0] * 60
        self.h = height
        self.w = width
        for i in range(0, width, 20): self.create_line(i, 0, i, height, fill=COLORS["grid_line"], width=1)
        for i in range(0, height, 20): self.create_line(0, i, width, i, fill=COLORS["grid_line"], width=1)

    def update_val(self, val):
        self.data.pop(0)
        self.data.append(val)
        self.delete("wave")
        m = max(self.data) if max(self.data) > 0 else 1
        normalized = [(v/m) * (self.h - 10) for v in self.data]
        points = [0, self.h]
        step = self.w / (len(self.data) - 1)
        for i, y in enumerate(normalized):
            points.append(i * step)
            points.append(self.h - y)
        points.extend([self.w, self.h])
        self.create_polygon(points, fill=self.color, stipple="gray25", outline="", tag="wave")
        if len(points) > 4: self.create_line(points[2:-2], fill=self.color, width=2, tag="wave")

# --- MAIN APP ---
class ProxyApp:
    def __init__(self, root):
        self.root = root
        self.root.overrideredirect(True) 
        self._force_taskbar()
        
        self.root.geometry("1100x700")
        self.root.configure(bg=COLORS["bg_void"])
        self._center_window()
        
        self.maximized = False
        self.pre_max_geometry = "1100x700"

        self.cfg_mgr = ConfigManager()
        self.config = self.cfg_mgr.config
        self.proxy = None
        self.start_time = 0
        self.stat_dl = 0
        self.stat_ul = 0
        self.detected_devices = {} 
        
        self.tray_icon = None  
        self.tray_image = None 

        self._setup_tray()
        self._build_custom_bar()
        self._build_main_layout()
        self._monitor_loop()

    def _force_taskbar(self):
        try:
            GWL_EXSTYLE = -20
            WS_EX_APPWINDOW = 0x00040000
            WS_EX_TOOLWINDOW = 0x00000080
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            style = style & ~WS_EX_TOOLWINDOW
            style = style | WS_EX_APPWINDOW
            ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style)
            self.root.wm_withdraw()
            self.root.after(10, lambda: self.root.wm_deiconify())
        except Exception: pass

    def _center_window(self):
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - 1100) // 2
        y = (sh - 700) // 2
        self.root.geometry(f"1100x700+{x}+{y}")

    def _build_custom_bar(self):
        self.title_bar = tk.Frame(self.root, bg=COLORS["bg_panel"], height=35)
        self.title_bar.pack(side="top", fill="x")
        self.title_bar.bind("<ButtonPress-1>", self._start_move)
        self.title_bar.bind("<ButtonRelease-1>", self._stop_move)
        self.title_bar.bind("<B1-Motion>", self._on_move)

        tk.Label(self.title_bar, text=" BAVO | GITHUB: https://github.com/bawanu ", fg=COLORS["neon_cyan"], bg=COLORS["bg_panel"], font=FONT_HEADER).pack(side="left", padx=15)
        
        btn_close = tk.Button(self.title_bar, text="×", bg=COLORS["bg_panel"], fg="white", bd=0, font=("Arial", 14), command=self._force_quit, activebackground="red")
        btn_close.pack(side="right", padx=5, pady=2, ipadx=10)
        
        btn_max = tk.Button(self.title_bar, text="□", bg=COLORS["bg_panel"], fg="white", bd=0, font=("Arial", 12), command=self._toggle_maximize)
        btn_max.pack(side="right", padx=0, pady=2, ipadx=10)

        btn_tray = tk.Button(self.title_bar, text="v", bg=COLORS["bg_panel"], fg="white", bd=0, font=("Consolas", 10, "bold"), command=self._minimize_to_tray)
        btn_tray.pack(side="right", padx=0, pady=2, ipadx=10)

    def _start_move(self, event):
        if not self.maximized:
            self.x = event.x
            self.y = event.y

    def _stop_move(self, event):
        self.x = None
        self.y = None

    def _on_move(self, event):
        if self.maximized: return
        if self.x is not None:
            deltax = event.x - self.x
            deltay = event.y - self.y
            x = self.root.winfo_x() + deltax
            y = self.root.winfo_y() + deltay
            self.root.geometry(f"+{x}+{y}")

    def _toggle_maximize(self):
        if self.maximized:
            self.root.geometry(self.pre_max_geometry)
            self.maximized = False
        else:
            self.pre_max_geometry = self.root.geometry()
            w, h = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
            self.root.geometry(f"{w}x{h}+0+0")
            self.maximized = True

    def _setup_tray(self):
        if not pystray: return
        try:
            self.tray_image = Image.new('RGB', (64, 64), color=(10, 10, 10))
            d = ImageDraw.Draw(self.tray_image)
            d.polygon([(32, 5), (5, 58), (59, 58)], fill=COLORS["neon_cyan_dim"], outline=COLORS["neon_cyan"])
        except Exception: self.tray_image = None

    def _minimize_to_tray(self):
        self.root.withdraw()
        if pystray and self.tray_image:
            menu = (pystray.MenuItem("Show", self._show_app, default=True), pystray.MenuItem("Exit", self._force_quit))
            self.tray_icon = pystray.Icon("BAVO", self.tray_image, "Bavo Proxy", menu)
            threading.Thread(target=self.tray_icon.run, daemon=True).start()
        
    def _show_app(self, icon, item):
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None 
        self.root.after(0, self.root.deiconify)

    def _force_quit(self, icon=None, item=None):
        if self.tray_icon:
            try: self.tray_icon.stop()
            except: pass
        if self.proxy: self.proxy.stop()
        self.root.destroy()
        os._exit(0) 

    def _build_main_layout(self):
        container = tk.Frame(self.root, bg=COLORS["bg_void"])
        container.pack(fill="both", expand=True)

        sidebar = tk.Frame(container, bg="#080808", width=220)
        sidebar.pack(side="left", fill="y")
        self._nav_btn(sidebar, "STATUS", self._show_dashboard)
        self._nav_btn(sidebar, "USERS", self._show_users)
        self._nav_btn(sidebar, "FIREWALL", self._show_firewall)
        self._nav_btn(sidebar, "CONNECTIONS", self._show_conns)
        self._nav_btn(sidebar, "LOGS", self._show_logs)
        self._nav_btn(sidebar, "CONFIG", self._show_settings)

        self.content = tk.Frame(container, bg=COLORS["bg_void"])
        self.content.pack(side="right", fill="both", expand=True, padx=20, pady=20)
        
        self.frames = {}
        self.frames["dash"] = self._frame_dashboard()
        self.frames["users"] = self._frame_users()
        self.frames["firewall"] = self._frame_firewall()
        self.frames["conns"] = self._frame_conns()
        self.frames["logs"] = self._frame_logs()
        self.frames["conf"] = self._frame_settings()
        self._show_dashboard()

    def _nav_btn(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, bg="#080808", fg=COLORS["text_dim"], font=FONT_UI, bd=0, 
                        activebackground=COLORS["bg_panel"], activeforeground=COLORS["neon_cyan"], 
                        command=cmd, pady=15, anchor="w", padx=20)
        btn.pack(fill="x")
        btn.bind("<Enter>", lambda e: btn.config(fg=COLORS["neon_cyan"], bg="#101010"))
        btn.bind("<Leave>", lambda e: btn.config(fg=COLORS["text_dim"], bg="#080808"))

    def _switch(self, key):
        for k, f in self.frames.items(): f.pack_forget()
        self.frames[key].pack(fill="both", expand=True)
        if key == "users": self._refresh_user_table()
        if key == "firewall": self._refresh_firewall_table()

    def _show_dashboard(self): self._switch("dash")
    def _show_users(self): self._switch("users")
    def _show_firewall(self): self._switch("firewall")
    def _show_conns(self): self._switch("conns")
    def _show_logs(self): self._switch("logs")
    def _show_settings(self): self._switch("conf")

    def _frame_dashboard(self):
        f = tk.Frame(self.content, bg=COLORS["bg_void"])
        top_row = tk.Frame(f, bg=COLORS["bg_void"])
        top_row.pack(fill="x", pady=10)
        
        info_box = tk.Frame(top_row, bg=COLORS["bg_void"], padx=15)
        info_box.pack(side="left")
        self.lbl_status_text = tk.Label(info_box, text="SYSTEM STANDBY", font=("Orbitron", 18), fg=COLORS["text_dim"], bg=COLORS["bg_void"])
        self.lbl_status_text.pack(anchor="w")
        self.lbl_uptime = tk.Label(info_box, text="T-MINUS: 00:00:00", font=FONT_MONO, fg=COLORS["text_dim"], bg=COLORS["bg_void"])
        self.lbl_uptime.pack(anchor="w")

        self.btn_toggle = CyberButton(top_row, "INITIALIZE CORE", self.toggle_server)
        self.btn_toggle.pack(side="right", anchor="center")

        graph_area = tk.Frame(f, bg=COLORS["bg_void"])
        graph_area.pack(fill="both", expand=True, pady=20)
        
        d_box = tk.Frame(graph_area, bg=COLORS["bg_panel"], padx=10, pady=10)
        d_box.pack(side="left", fill="both", expand=True, padx=(0, 10))
        tk.Label(d_box, text="INBOUND STREAM (DL)", fg=COLORS["neon_cyan"], bg=COLORS["bg_panel"], font=FONT_MONO).pack(anchor="w")
        self.graph_dl = Oscilloscope(d_box, COLORS["neon_cyan"])
        self.graph_dl.pack(fill="both", expand=True)
        self.lbl_speed_dl = tk.Label(d_box, text="0 KB/s", fg="white", bg=COLORS["bg_panel"], font=("Orbitron", 20))
        self.lbl_speed_dl.pack(anchor="e")

        u_box = tk.Frame(graph_area, bg=COLORS["bg_panel"], padx=10, pady=10)
        u_box.pack(side="right", fill="both", expand=True, padx=(10, 0))
        tk.Label(u_box, text="OUTBOUND STREAM (UL)", fg=COLORS["neon_purple"], bg=COLORS["bg_panel"], font=FONT_MONO).pack(anchor="w")
        self.graph_ul = Oscilloscope(u_box, COLORS["neon_purple"])
        self.graph_ul.pack(fill="both", expand=True)
        self.lbl_speed_ul = tk.Label(u_box, text="0 KB/s", fg="white", bg=COLORS["bg_panel"], font=("Orbitron", 20))
        self.lbl_speed_ul.pack(anchor="e")
        return f

    def _frame_firewall(self):
        f = tk.Frame(self.content, bg=COLORS["bg_void"])
        tk.Label(f, text="FIREWALL & BLOCKED HOSTS", fg=COLORS["danger"], bg=COLORS["bg_void"], font=FONT_HEADER).pack(anchor="w", pady=(0, 15))
        btn_box = tk.Frame(f, bg=COLORS["bg_void"])
        btn_box.pack(fill="x", pady=(0, 10))
        tk.Button(btn_box, text="UNBLOCK SELECTED", bg=COLORS["neon_cyan_dim"], fg="white", bd=0, padx=15, pady=8, command=self._unblock_selected).pack(side="left", padx=(0, 10))
        tk.Button(btn_box, text="PANIC: BLOCK ALL ACTIVE", bg=COLORS["danger"], fg="white", bd=0, padx=15, pady=8, command=self._panic_block_all).pack(side="right")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#0a0a0a", foreground="white", fieldbackground="#0a0a0a", borderwidth=0)
        style.configure("Treeview.Heading", background="#222", foreground=COLORS["danger"], font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", COLORS["danger_dim"])])

        self.fw_tree = ttk.Treeview(f, columns=("ip", "name", "date"), show="headings")
        self.fw_tree.heading("ip", text="BLOCKED IP")
        self.fw_tree.heading("name", text="ALIAS")
        self.fw_tree.heading("date", text="STATUS")
        self.fw_tree.column("ip", width=150)
        self.fw_tree.column("name", width=150)
        self.fw_tree.pack(fill="both", expand=True)
        
        self.fw_menu = Menu(f, tearoff=0, bg="#222", fg="white")
        self.fw_menu.add_command(label="Unblock", command=self._unblock_selected)
        self.fw_tree.bind("<Button-3>", lambda e: self.fw_menu.tk_popup(e.x_root, e.y_root))
        return f

    def _frame_users(self):
        f = tk.Frame(self.content, bg=COLORS["bg_void"])
        tk.Label(f, text="USER MANAGEMENT", fg=COLORS["neon_cyan"], bg=COLORS["bg_void"], font=FONT_HEADER).pack(anchor="w", pady=(0, 15))

        input_frame = tk.Frame(f, bg=COLORS["bg_panel"], pady=10, padx=10)
        input_frame.pack(fill="x", pady=(0, 10))
        
        self.u_ip = tk.StringVar()
        self.u_name = tk.StringVar()
        self.u_limit = tk.StringVar(value="0")
        self.u_black = tk.StringVar()

        def _e(p, var, ph, r, c, w=1):
            tk.Label(p, text=ph, bg=COLORS["bg_panel"], fg="gray", font=("Consolas", 8)).grid(row=r, column=c, sticky="w", padx=5)
            tk.Entry(p, textvariable=var, bg="#222", fg="white", insertbackground="white", bd=0).grid(row=r+1, column=c, sticky="ew", padx=5, pady=(0, 10), columnspan=w)

        input_frame.columnconfigure(0, weight=1)
        input_frame.columnconfigure(1, weight=1)
        input_frame.columnconfigure(2, weight=1)

        _e(input_frame, self.u_ip, "IP ADDRESS", 0, 0)
        _e(input_frame, self.u_name, "USERNAME/ALIAS", 0, 1)
        _e(input_frame, self.u_limit, "SPEED LIMIT (KB/s)", 0, 2)

        tk.Label(input_frame, text="USER BLACKLIST (CSV)", bg=COLORS["bg_panel"], fg="gray", font=("Consolas", 8)).grid(row=2, column=0, sticky="w", padx=5)
        tk.Entry(input_frame, textvariable=self.u_black, bg="#222", fg="white", insertbackground="white", bd=0).grid(row=3, column=0, columnspan=3, sticky="ew", padx=5, pady=(0, 10))

        btn_box = tk.Frame(input_frame, bg=COLORS["bg_panel"])
        btn_box.grid(row=4, column=0, columnspan=3, sticky="e", pady=5)
        tk.Button(btn_box, text="ADD / UPDATE", bg=COLORS["neon_cyan_dim"], fg="white", bd=0, padx=15, pady=5, command=self._add_user).pack(side="left", padx=5)
        tk.Button(btn_box, text="EDIT SELECTED", bg=COLORS["neon_purple_dim"], fg="white", bd=0, padx=15, pady=5, command=self._load_user_for_edit).pack(side="left", padx=5)
        tk.Button(btn_box, text="BLOCK IP", bg="#ff0000", fg="white", bd=0, padx=15, pady=5, command=self._block_user).pack(side="left", padx=5)

        self.user_tree = ttk.Treeview(f, columns=("ip", "name", "device", "limit", "bl_count"), show="headings")
        self.user_tree.heading("ip", text="IP ADDRESS")
        self.user_tree.heading("name", text="USER ALIAS")
        self.user_tree.heading("device", text="DETECTED DEVICE")
        self.user_tree.heading("limit", text="LIMIT")
        self.user_tree.heading("bl_count", text="BLACKLIST")
        self.user_tree.column("ip", width=120)
        self.user_tree.column("name", width=100)
        self.user_tree.pack(fill="both", expand=True)

        self.u_menu = Menu(f, tearoff=0, bg="#222", fg="white")
        self.u_menu.add_command(label="Block IP", command=self._block_user)
        self.u_menu.add_command(label="Copy IP", command=self._copy_user_ip)
        self.user_tree.bind("<Button-3>", lambda e: self.u_menu.tk_popup(e.x_root, e.y_root))
        return f

    def _frame_conns(self):
        f = tk.Frame(self.content, bg=COLORS["bg_void"])
        tk.Label(f, text="ACTIVE NEURAL LINKS", fg=COLORS["neon_cyan"], bg=COLORS["bg_void"], font=FONT_HEADER).pack(anchor="w", pady=(0, 15))
        self.conn_tree = ttk.Treeview(f, columns=("src", "dst", "duration"), show="headings")
        self.conn_tree.heading("src", text="SOURCE NODE")
        self.conn_tree.heading("dst", text="TARGET HOST")
        self.conn_tree.heading("duration", text="DURATION")
        self.conn_tree.column("src", width=200)
        self.conn_tree.column("dst", width=350)
        self.conn_tree.pack(fill="both", expand=True)
        self.c_menu = Menu(f, tearoff=0, bg="#222", fg="white")
        self.c_menu.add_command(label="Block Source IP", command=self._block_conn_ip)
        self.c_menu.add_command(label="Disconnect", command=self._disconnect_conn)
        self.conn_tree.bind("<Button-3>", lambda e: self.c_menu.tk_popup(e.x_root, e.y_root))
        return f

    def _frame_logs(self):
        f = tk.Frame(self.content, bg=COLORS["bg_void"])
        tk.Label(f, text="SYSTEM EVENT LOG", fg=COLORS["neon_cyan"], bg=COLORS["bg_void"], font=FONT_HEADER).pack(anchor="w", pady=(0, 15))
        self.log_area = scrolledtext.ScrolledText(f, bg="#000000", fg="#33ff33", font=("Consolas", 10), bd=0)
        self.log_area.pack(fill="both", expand=True)
        btn_clr = tk.Button(f, text="PURGE LOGS", bg="#222", fg="white", bd=0, command=lambda: self.log_area.delete(1.0, tk.END))
        btn_clr.pack(fill="x", pady=5)
        return f

    def _frame_settings(self):
        # Main container
        f = tk.Frame(self.content, bg=COLORS["bg_void"])
        
        # 1. Create a Canvas and a Scrollbar
        canvas = tk.Canvas(f, bg=COLORS["bg_void"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(f, orient="vertical", command=canvas.yview)
        # This frame will hold the actual content
        scrollable_frame = tk.Frame(canvas, bg=COLORS["bg_void"])

        # 2. Configure scrolling
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # 3. Handle Mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # --- CONTENT START (Reparented to scrollable_frame) ---
        tk.Label(scrollable_frame, text="CORE CONFIGURATION", fg=COLORS["neon_cyan"], bg=COLORS["bg_void"], font=FONT_HEADER).pack(anchor="w", pady=(0, 20))

        def _row(parent, label, var, row):
            tk.Label(parent, text=label, fg=COLORS["text_main"], bg=COLORS["bg_void"], font=FONT_UI).grid(row=row, column=0, sticky="w", pady=8)
            e = tk.Entry(parent, textvariable=var, bg="#222", fg="white", insertbackground="white", bd=0, highlightthickness=1, highlightcolor=COLORS["neon_cyan"])
            e.grid(row=row, column=1, sticky="ew", padx=20)
            return e

        form = tk.Frame(scrollable_frame, bg=COLORS["bg_void"])
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)

        self.sv_host = tk.StringVar(value=self.config["host"])
        self.sv_port = tk.StringVar(value=self.config["port"])
        self.sv_user = tk.StringVar(value=self.config["username"])
        self.sv_pass = tk.StringVar(value=self.config["password"])
        self.sv_ips = tk.StringVar(value=self.config["whitelist_ips"])
        self.sv_black = tk.StringVar(value=self.config["blacklist_domains"])
        self.sv_speed = tk.StringVar(value=self.config["speed_limit_kbps"])
        self.sv_max_conn = tk.StringVar(value=self.config.get("max_conns_per_ip", 50))

        _row(form, "BIND IP", self.sv_host, 0)
        _row(form, "PORT", self.sv_port, 1)
        _row(form, "USERNAME", self.sv_user, 2)
        _row(form, "PASSWORD", self.sv_pass, 3)
        _row(form, "WHITELIST IPS", self.sv_ips, 4)
        _row(form, "GLOBAL BLACKLIST", self.sv_black, 5)
        _row(form, "GLOBAL SPEED LIMIT (KBps)", self.sv_speed, 6)
        _row(form, "MAX CONNS PER IP", self.sv_max_conn, 7)

        self.bv_auth = tk.BooleanVar(value=self.config["auth_enabled"])
        self.bv_white = tk.BooleanVar(value=self.config["whitelist_enabled"])
        
        tk.Checkbutton(form, text="ENABLE AUTHENTICATION", variable=self.bv_auth, bg=COLORS["bg_void"], fg="white", selectcolor="#222", activebackground=COLORS["bg_void"]).grid(row=8, column=0, sticky="w")
        tk.Checkbutton(form, text="ENABLE IP WHITELIST", variable=self.bv_white, bg=COLORS["bg_void"], fg="white", selectcolor="#222", activebackground=COLORS["bg_void"]).grid(row=9, column=0, sticky="w")

        btn_save = tk.Button(scrollable_frame, text="FLASH MEMORY (SAVE)", bg=COLORS["neon_purple_dim"], fg="white", font=FONT_UI, bd=0, padx=20, pady=10, command=self.save_config)
        btn_save.pack(pady=30, anchor="w")
        # --- CONTENT END ---

        # Pack the scrollbar and canvas
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        return f

    def log(self, msg):
        timestamp = time.strftime("%H:%M:%S")
        def _add():
            if not self.root.winfo_exists(): return
            self.log_area.insert(tk.END, f"[{timestamp}] {msg}\n")
            self.log_area.see(tk.END)
        try: self.root.after(0, _add)
        except: pass

    def toggle_server(self):
        if self.proxy and self.proxy.running:
            self.proxy.stop()
            self.btn_toggle.set_state(False, "INITIALIZE CORE")
            self.lbl_status_text.config(text="SYSTEM STANDBY", fg=COLORS["text_dim"])
        else:
            self.config = self.cfg_mgr.config 
            self.proxy = ProxyEngine(self.config, self.log, self.update_traffic, self.update_conns_ui, self.update_detected_user)
            self.proxy.start()
            self.start_time = time.time()
            self.btn_toggle.set_state(True, "TERMINATE CORE")
            self.lbl_status_text.config(text=f"ONLINE :: PORT {self.config['port']}", fg=COLORS["neon_cyan"])

    def update_traffic(self, dl, ul):
        self.stat_dl += dl
        self.stat_ul += ul

    def update_conns_ui(self, active_dict):
        def _u():
            if not self.root.winfo_exists(): return
            for item in self.conn_tree.get_children(): self.conn_tree.delete(item)
            now = time.time()
            for k, v in active_dict.items():
                dur = int(now - v.get('ts', now))
                self.conn_tree.insert('', 'end', values=(v['src'], v['dst'], f"{dur}s"))
        self.root.after(0, _u)

    def update_detected_user(self, ip, device_info):
        # Persistence: Add to detected dict but never remove
        self.detected_devices[ip] = device_info
        self.root.after(0, self._refresh_user_table)

    def _add_user(self):
        ip = self.u_ip.get().strip()
        name = self.u_name.get().strip()
        blacklist = self.u_black.get().strip()
        try: limit = int(self.u_limit.get())
        except: limit = 0
        if ip:
            existing = self.config["users"].get(ip, {})
            existing.pop("banned", None)
            self.config["users"][ip] = {
                "name": name, 
                "limit": limit, 
                "blacklist": blacklist
            }
            self.cfg_mgr.save(self.config)
            if self.proxy and self.proxy.running:
                self.proxy.refresh_config(self.config)
            self._refresh_user_table()
            self.log(f"[CONFIG] USER UPDATED: {name} @ {ip}")
            self._clear_inputs()

    def _clear_inputs(self):
        self.u_ip.set("")
        self.u_name.set("")
        self.u_limit.set("0")
        self.u_black.set("")

    def _load_user_for_edit(self):
        sel = self.user_tree.selection()
        if not sel: return
        val = self.user_tree.item(sel[0])['values']
        ip = str(val[0])
        user_data = self.config["users"].get(ip)
        if user_data:
            self.u_ip.set(ip)
            self.u_name.set(user_data.get("name", ""))
            self.u_limit.set(user_data.get("limit", 0))
            self.u_black.set(user_data.get("blacklist", ""))
        else:
            self.u_ip.set(ip)
            self.u_name.set(val[1])

    def _block_user(self):
        sel = self.user_tree.selection()
        if not sel: return
        val = self.user_tree.item(sel[0])['values']
        ip = str(val[0])
        self._execute_block(ip)

    def _block_conn_ip(self):
        sel = self.conn_tree.selection()
        if not sel: return
        val = self.conn_tree.item(sel[0])['values']
        if not val: return
        try:
            ip_str = val[0].replace('(', '').replace(')', '').replace("'", "")
            ip = ip_str.split(',')[0].strip()
            self._execute_block(ip)
        except: pass

    def _execute_block(self, ip):
        if ip not in self.config["users"]:
            self.config["users"][ip] = {}
        self.config["users"][ip]["banned"] = True
        self.config["users"][ip]["name"] = self.config["users"][ip].get("name", "BANNED USER")
        self.cfg_mgr.save(self.config)
        if self.proxy and self.proxy.running:
            self.proxy.refresh_config(self.config)
            c = self.proxy.flush_connections(target_ip=ip)
            self.log(f"[ADMIN] BLOCKED IP {ip}. {c} CONNECTIONS DROPPED.")
        else:
            self.log(f"[ADMIN] IP {ip} ADDED TO BAN LIST.")
        self._refresh_user_table()
        self._refresh_firewall_table()

    def _unblock_selected(self):
        sel = self.fw_tree.selection()
        if not sel: return
        for item in sel:
            val = self.fw_tree.item(item)['values']
            ip = str(val[0])
            if ip in self.config["users"]:
                u = self.config["users"][ip]
                if "banned" in u:
                    del u["banned"]
                    if len(u) <= 1: 
                        del self.config["users"][ip]
                self.log(f"[ADMIN] UNBLOCKED IP {ip}")
        self.cfg_mgr.save(self.config)
        if self.proxy: self.proxy.refresh_config(self.config)
        self._refresh_user_table()
        self._refresh_firewall_table()

    def _panic_block_all(self):
        if not self.proxy or not self.proxy.running: return
        count = 0
        whitelist = [x.strip() for x in self.config["whitelist_ips"].split(',')]
        active_ips = set(self.detected_devices.keys())
        for ip in active_ips:
            if ip not in whitelist:
                self._execute_block(ip)
                count += 1
        self.log(f"[PANIC] EXECUTED MASS BLOCK ON {count} IPS.")

    def _disconnect_conn(self):
        sel = self.conn_tree.selection()
        if not sel: return
        val = self.conn_tree.item(sel[0])['values']
        try:
            ip_str = val[0].replace('(', '').replace(')', '').replace("'", "")
            ip = ip_str.split(',')[0].strip()
            if self.proxy:
                self.proxy.flush_connections(target_ip=ip)
                self.log(f"[ADMIN] KICKED {ip}")
        except: pass

    def _copy_user_ip(self):
        sel = self.user_tree.selection()
        if sel:
            ip = str(self.user_tree.item(sel[0])['values'][0])
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)

    def _refresh_user_table(self):
        if not self.root.winfo_exists(): return
        for item in self.user_tree.get_children(): self.user_tree.delete(item)
        # Persistent Users: Combine saved users and every detected IP since startup
        all_ips = set(list(self.config["users"].keys()) + list(self.detected_devices.keys()))
        for ip in all_ips:
            saved = self.config["users"].get(ip, {})
            if saved.get("banned", False): continue
            name = saved.get("name", "GUEST")
            limit = saved.get("limit", 0)
            blacklist = saved.get("blacklist", "")
            bl_count = len([x for x in blacklist.split(',') if x.strip()])
            device = self.detected_devices.get(ip, "Unknown")
            limit_str = "Global" if limit == 0 else f"{limit} KB/s"
            self.user_tree.insert('', 'end', values=(ip, name, device, limit_str, f"{bl_count} Domains"))

    def _refresh_firewall_table(self):
        if not self.root.winfo_exists(): return
        for item in self.fw_tree.get_children(): self.fw_tree.delete(item)
        for ip, data in self.config["users"].items():
            if data.get("banned", False):
                self.fw_tree.insert('', 'end', values=(ip, data.get("name", "Unknown"), "DENIED"))

    def save_config(self):
        try:
            cfg = {
                "host": self.sv_host.get(),
                "port": int(self.sv_port.get()),
                "auth_enabled": self.bv_auth.get(),
                "username": self.sv_user.get(),
                "password": self.sv_pass.get(),
                "whitelist_enabled": self.bv_white.get(),
                "whitelist_ips": self.sv_ips.get(),
                "blacklist_domains": self.sv_black.get(),
                "speed_limit_kbps": int(self.sv_speed.get()),
                "max_conns_per_ip": int(self.sv_max_conn.get()),
                "users": self.config["users"]
            }
            self.cfg_mgr.save(cfg)
            if self.proxy and self.proxy.running:
                self.proxy.refresh_config(cfg)
                self.proxy.flush_connections()
                self.log(f"[CONFIG] SAVED. CONNECTIONS FLUSHED.")
            else:
                self.log("[CONFIG] SAVED (OFFLINE).")
            messagebox.showinfo("SYSTEM", "CONFIGURATION APPLIED")
        except ValueError:
            messagebox.showerror("ERROR", "INVALID NUMERIC INPUT")

    def _monitor_loop(self):
        def _loop():
            while True:
                time.sleep(0.5)
                if self.proxy and self.proxy.running:
                    ds = self.stat_dl * 2 / 1024
                    us = self.stat_ul * 2 / 1024
                    self.stat_dl = 0
                    self.stat_ul = 0
                    elapsed = time.time() - self.start_time
                    uptime = time.strftime("%H:%M:%S", time.gmtime(elapsed))
                    self.root.after(0, lambda: self._update_ui_realtime(ds, us, uptime))
        t = threading.Thread(target=_loop, daemon=True)
        t.start()

    def _update_ui_realtime(self, ds, us, uptime):
        if self.root.winfo_exists():
            self.lbl_speed_dl.config(text=f"{ds:.1f} KB/s")
            self.lbl_speed_ul.config(text=f"{us:.1f} KB/s")
            self.lbl_uptime.config(text=f"UPTIME: {uptime}")
            self.graph_dl.update_val(ds)
            self.graph_ul.update_val(us)

if __name__ == "__main__":
    root = tk.Tk()
    app = ProxyApp(root)
    root.mainloop()
