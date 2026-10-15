import ctypes
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from typing import Optional

from engine import ProxyEngine, load_config_file, save_config_file


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def restart_as_admin():
    try:
        script = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        sys.exit(0)
    except Exception as e:
        messagebox.showerror("خطا", f"امکان اجرای با دسترسی ادمین میسر نشد: {e}")


class BypassApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SNI Spoofing & DPI Bypass Panel")
        self.geometry("860x780")
        self.minsize(800, 700)

        # Apply modern dark theme colors
        self.bg_color = "#18191c"
        self.fg_color = "#e1e2e6"
        self.card_bg = "#232428"
        self.card_border = "#313338"
        self.accent_color = "#5865f2"
        self.success_color = "#3ba55d"
        self.danger_color = "#ed4245"
        self.warning_color = "#faa81a"

        self.configure(bg=self.bg_color)

        self.engine: Optional[ProxyEngine] = None
        self.config_data = load_config_file()

        self._setup_styles()
        self._build_ui()
        self._load_config_into_ui()

    def _setup_styles(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        self.style.configure(".", background=self.bg_color, foreground=self.fg_color, font=("Segoe UI", 9))
        self.style.configure("TLabel", background=self.bg_color, foreground=self.fg_color)
        self.style.configure("Card.TFrame", background=self.card_bg, relief="flat")
        self.style.configure("CardLabel.TLabel", background=self.card_bg, foreground=self.fg_color, font=("Segoe UI", 9))
        self.style.configure("CardHeader.TLabel", background=self.card_bg, foreground=self.accent_color, font=("Segoe UI", 10, "bold"))

        self.style.configure("TCheckbutton", background=self.card_bg, foreground=self.fg_color, font=("Segoe UI", 9))
        self.style.map("TCheckbutton", background=[("active", self.card_bg)], foreground=[("active", "#ffffff")])

        self.style.configure("TEntry", fieldbackground="#2b2d31", foreground="#ffffff", insertcolor="#ffffff")
        self.style.configure("TSpinbox", fieldbackground="#2b2d31", foreground="#ffffff", insertcolor="#ffffff")
        self.style.configure("TCombobox", fieldbackground="#2b2d31", foreground="#ffffff")

    def _build_ui(self):
        # 1. Admin Warning Banner (if not admin)
        if not is_admin():
            admin_banner = tk.Frame(self, bg=self.warning_color, padx=10, pady=6)
            admin_banner.pack(fill="x", side="top")
            lbl = tk.Label(
                admin_banner,
                text="⚠️ برنامه با دسترسی Administrator اجرا نشده است. درایور WinDivert نیاز به دسترسی ادمین دارد.",
                bg=self.warning_color,
                fg="#000000",
                font=("Segoe UI", 9, "bold")
            )
            lbl.pack(side="left", padx=5)
            btn_admin = tk.Button(
                admin_banner,
                text="اجرا با دسترسی Administrator",
                command=restart_as_admin,
                bg="#000000",
                fg="#ffffff",
                relief="flat",
                font=("Segoe UI", 8, "bold"),
                cursor="hand2"
            )
            btn_admin.pack(side="right", padx=5)

        # Main scrollable or padded container
        main_frame = tk.Frame(self, bg=self.bg_color, padx=15, pady=10)
        main_frame.pack(fill="both", expand=True)

        # 2. Header & Status Section
        header_frame = tk.Frame(main_frame, bg=self.bg_color)
        header_frame.pack(fill="x", pady=(0, 10))

        title_lbl = tk.Label(
            header_frame,
            text="SNI Spoofing & TCP Bypass Proxy",
            bg=self.bg_color,
            fg="#ffffff",
            font=("Segoe UI", 14, "bold")
        )
        title_lbl.pack(side="left")

        self.status_badge = tk.Label(
            header_frame,
            text="● وضعیت: متوقف",
            bg=self.card_bg,
            fg=self.danger_color,
            font=("Segoe UI", 10, "bold"),
            padx=12,
            pady=4,
            relief="solid",
            bd=1
        )
        self.status_badge.pack(side="right")

        # 3. Connection Settings Card
        conn_card = tk.LabelFrame(
            main_frame,
            text=" تنظیمات شبکه و پروکسی (Proxy Settings) ",
            bg=self.card_bg,
            fg=self.accent_color,
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=10
        )
        conn_card.pack(fill="x", pady=5)

        # Row 1: Listen Host & Port
        tk.Label(conn_card, text="Listen Host:", bg=self.card_bg, fg=self.fg_color).grid(row=0, column=0, sticky="w", pady=4)
        self.ent_listen_host = ttk.Entry(conn_card, width=16)
        self.ent_listen_host.grid(row=0, column=1, sticky="w", padx=(5, 20), pady=4)

        tk.Label(conn_card, text="Listen Port:", bg=self.card_bg, fg=self.fg_color).grid(row=0, column=2, sticky="w", pady=4)
        self.ent_listen_port = ttk.Entry(conn_card, width=10)
        self.ent_listen_port.grid(row=0, column=3, sticky="w", padx=(5, 20), pady=4)

        # Row 2: Connect IP & Port
        tk.Label(conn_card, text="Target (CDN/Server) IP:", bg=self.card_bg, fg=self.fg_color).grid(row=1, column=0, sticky="w", pady=4)
        self.ent_connect_ip = ttk.Entry(conn_card, width=16)
        self.ent_connect_ip.grid(row=1, column=1, sticky="w", padx=(5, 20), pady=4)

        tk.Label(conn_card, text="Target Port:", bg=self.card_bg, fg=self.fg_color).grid(row=1, column=2, sticky="w", pady=4)
        self.ent_connect_port = ttk.Entry(conn_card, width=10)
        self.ent_connect_port.grid(row=1, column=3, sticky="w", padx=(5, 20), pady=4)

        # Row 3: Fake SNI
        tk.Label(conn_card, text="Fake SNI (مجاز / سفید):", bg=self.card_bg, fg=self.fg_color).grid(row=2, column=0, sticky="w", pady=4)
        self.ent_fake_sni = ttk.Entry(conn_card, width=32)
        self.ent_fake_sni.grid(row=2, column=1, columnspan=3, sticky="w", padx=5, pady=4)

        # 4. Bypass Strategies Card
        strat_card = tk.LabelFrame(
            main_frame,
            text=" تکنیک‌های دور زدن فیلترینگ (Bypass Strategies) ",
            bg=self.card_bg,
            fg=self.accent_color,
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=10
        )
        strat_card.pack(fill="x", pady=5)

        # Toggles Variables
        self.var_wrong_seq = tk.BooleanVar(value=True)
        self.var_low_ttl = tk.BooleanVar(value=False)
        self.var_fake_ttl = tk.IntVar(value=5)
        self.var_wrong_chksum = tk.BooleanVar(value=False)
        self.var_fake_rst = tk.BooleanVar(value=False)
        self.var_fake_http = tk.BooleanVar(value=False)
        self.var_tls_frag = tk.BooleanVar(value=False)
        self.var_frag_mode = tk.StringVar(value="sni")
        self.var_fake_ech = tk.BooleanVar(value=False)
        self.var_tcp_overlap = tk.BooleanVar(value=False)
        self.var_use_npcap = tk.BooleanVar(value=True)

        # Left Column
        col1 = tk.Frame(strat_card, bg=self.card_bg)
        col1.pack(side="left", fill="both", expand=True, padx=5)

        ttk.Checkbutton(
            col1,
            text="Wrong Seq (بای‌پس اصلی با شماره توالی ناهماهنگ)",
            variable=self.var_wrong_seq
        ).pack(anchor="w", pady=3)

        ttl_frame = tk.Frame(col1, bg=self.card_bg)
        ttl_frame.pack(anchor="w", fill="x", pady=3)
        ttk.Checkbutton(
            ttl_frame,
            text="Low TTL (تزریق پکت جعلی با TTL محدود):",
            variable=self.var_low_ttl
        ).pack(side="left")
        spn_ttl = ttk.Spinbox(ttl_frame, from_=2, to=15, width=4, textvariable=self.var_fake_ttl)
        spn_ttl.pack(side="left", padx=5)

        ttk.Checkbutton(
            col1,
            text="Wrong Checksum (چک‌سام ناقص TCP برای نادیده گرفتن سرور)",
            variable=self.var_wrong_chksum
        ).pack(anchor="w", pady=3)

        ttk.Checkbutton(
            col1,
            text="Fake RST State Poisoning (تزریق RST فیک برای فریب جدول DPI)",
            variable=self.var_fake_rst
        ).pack(anchor="w", pady=3)

        ttk.Checkbutton(
            col1,
            text="Protocol Confusion (ارسال پروب جعلی HTTP قبل از TLS)",
            variable=self.var_fake_http
        ).pack(anchor="w", pady=3)

        # Right Column
        col2 = tk.Frame(strat_card, bg=self.card_bg)
        col2.pack(side="left", fill="both", expand=True, padx=5)

        frag_frame = tk.Frame(col2, bg=self.card_bg)
        frag_frame.pack(anchor="w", fill="x", pady=3)
        ttk.Checkbutton(
            frag_frame,
            text="TLS SNI Fragmentation (تکه‌تکه کردن هدر):",
            variable=self.var_tls_frag
        ).pack(side="left")
        cmb_frag = ttk.Combobox(
            frag_frame,
            textvariable=self.var_frag_mode,
            values=["sni", "record_header", "tiny"],
            width=11,
            state="readonly"
        )
        cmb_frag.pack(side="left", padx=5)

        ttk.Checkbutton(
            col2,
            text="Fake ECH Extension (تزریق افزونه رمزنگاری شده ECH)",
            variable=self.var_fake_ech
        ).pack(anchor="w", pady=3)

        ttk.Checkbutton(
            col2,
            text="TCP Overlap (هم‌پوشانی شماره توالی با پکت واقعی)",
            variable=self.var_tcp_overlap
        ).pack(anchor="w", pady=3)

        ttk.Checkbutton(
            col2,
            text="Direct NIC via Npcap (تزریق مستقیم به کارت شبکه با Npcap)",
            variable=self.var_use_npcap
        ).pack(anchor="w", pady=3)

        # 5. Action Buttons (Big Start/Stop + Save)
        action_frame = tk.Frame(main_frame, bg=self.bg_color)
        action_frame.pack(fill="x", pady=8)

        self.btn_toggle = tk.Button(
            action_frame,
            text="▶ شروع سرویس (START)",
            command=self.toggle_service,
            bg=self.success_color,
            fg="#ffffff",
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            padx=25,
            pady=8,
            cursor="hand2"
        )
        self.btn_toggle.pack(side="left", padx=(0, 10))

        btn_save = tk.Button(
            action_frame,
            text="ذخیره تنظیمات (Save)",
            command=self.save_settings,
            bg="#2b2d31",
            fg=self.fg_color,
            font=("Segoe UI", 9),
            relief="flat",
            padx=15,
            pady=8,
            cursor="hand2"
        )
        btn_save.pack(side="left", padx=5)

        btn_clear = tk.Button(
            action_frame,
            text="پاک کردن لاگ",
            command=self.clear_logs,
            bg="#2b2d31",
            fg=self.fg_color,
            font=("Segoe UI", 9),
            relief="flat",
            padx=12,
            pady=8,
            cursor="hand2"
        )
        btn_clear.pack(side="right")

        # 6. Real-time Log Console
        log_card = tk.LabelFrame(
            main_frame,
            text=" لاگ و رخدادهای زنده (Live Events) ",
            bg=self.card_bg,
            fg=self.accent_color,
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=6
        )
        log_card.pack(fill="both", expand=True, pady=(5, 0))

        self.txt_log = scrolledtext.ScrolledText(
            log_card,
            bg="#121315",
            fg="#cccccc",
            insertbackground="#ffffff",
            font=("Consolas", 9),
            relief="flat",
            wrap="word",
            state="disabled"
        )
        self.txt_log.pack(fill="both", expand=True)

        # Configure log text tags for styling
        self.txt_log.tag_config("info", foreground="#5865f2")
        self.txt_log.tag_config("success", foreground="#3ba55d")
        self.txt_log.tag_config("warning", foreground="#faa81a")
        self.txt_log.tag_config("error", foreground="#ed4245")
        self.txt_log.tag_config("frag", foreground="#e67e22")

    def _load_config_into_ui(self):
        c = self.config_data
        self.ent_listen_host.delete(0, tk.END)
        self.ent_listen_host.insert(0, c.get("LISTEN_HOST", "0.0.0.0"))

        self.ent_listen_port.delete(0, tk.END)
        self.ent_listen_port.insert(0, str(c.get("LISTEN_PORT", 40443)))

        self.ent_connect_ip.delete(0, tk.END)
        self.ent_connect_ip.insert(0, c.get("CONNECT_IP", "188.114.98.0"))

        self.ent_connect_port.delete(0, tk.END)
        self.ent_connect_port.insert(0, str(c.get("CONNECT_PORT", 443)))

        self.ent_fake_sni.delete(0, tk.END)
        self.ent_fake_sni.insert(0, c.get("FAKE_SNI", "auth.vercel.com"))

        opts = c.get("BYPASS_OPTIONS", {})
        self.var_wrong_seq.set(opts.get("wrong_seq", True))
        self.var_low_ttl.set(opts.get("low_ttl", False))
        self.var_fake_ttl.set(opts.get("fake_ttl", 5))
        self.var_wrong_chksum.set(opts.get("wrong_chksum", False))
        self.var_fake_rst.set(opts.get("fake_rst", False))
        self.var_fake_http.set(opts.get("fake_http", False))
        self.var_tls_frag.set(opts.get("tls_frag", False))
        self.var_frag_mode.set(opts.get("frag_mode", "sni"))
        self.var_fake_ech.set(opts.get("fake_ech", False))
        self.var_tcp_overlap.set(opts.get("tcp_overlap", False))
        self.var_use_npcap.set(opts.get("use_npcap", True))

        self.append_log("[i] کانفیگ با موفقیت بارگذاری شد. آماده اتصال به v2rayN.")

    def get_ui_config(self) -> dict:
        return {
            "LISTEN_HOST": self.ent_listen_host.get().strip(),
            "LISTEN_PORT": int(self.ent_listen_port.get().strip()),
            "CONNECT_IP": self.ent_connect_ip.get().strip(),
            "CONNECT_PORT": int(self.ent_connect_port.get().strip()),
            "FAKE_SNI": self.ent_fake_sni.get().strip(),
            "BYPASS_OPTIONS": {
                "wrong_seq": self.var_wrong_seq.get(),
                "low_ttl": self.var_low_ttl.get(),
                "fake_ttl": self.var_fake_ttl.get(),
                "wrong_chksum": self.var_wrong_chksum.get(),
                "fake_rst": self.var_fake_rst.get(),
                "fake_http": self.var_fake_http.get(),
                "tls_frag": self.var_tls_frag.get(),
                "frag_mode": self.var_frag_mode.get(),
                "fake_ech": self.var_fake_ech.get(),
                "tcp_overlap": self.var_tcp_overlap.get(),
                "use_npcap": self.var_use_npcap.get(),
            }
        }

    def save_settings(self):
        try:
            cfg = self.get_ui_config()
            save_config_file(cfg)
            self.append_log("[✓] تنظیمات با موفقیت در config.json ذخیره شد.")
        except Exception as e:
            messagebox.showerror("خطا", f"ذخیره تنظیمات با خطا مواجه شد: {e}")

    def append_log(self, text: str):
        def _insert():
            self.txt_log.configure(state="normal")
            tag = "info"
            if "[✓]" in text:
                tag = "success"
            elif "[-]" in text or "خطا" in text:
                tag = "error"
            elif "[FRAG]" in text:
                tag = "frag"
            elif "[*]" in text or "[i]" in text:
                tag = "info"
            elif "[+]" in text:
                tag = "success"

            self.txt_log.insert(tk.END, text + "\n", tag)
            self.txt_log.see(tk.END)
            self.txt_log.configure(state="disabled")

        self.after(0, _insert)

    def clear_logs(self):
        self.txt_log.configure(state="normal")
        self.txt_log.delete(1.0, tk.END)
        self.txt_log.configure(state="disabled")

    def toggle_service(self):
        if self.engine and self.engine.is_running:
            self._stop_service()
        else:
            self._start_service()

    def _start_service(self):
        try:
            cfg = self.get_ui_config()
            save_config_file(cfg)
            self.engine = ProxyEngine(cfg, log_callback=self.append_log)
            self.engine.start()

            self.btn_toggle.configure(text="⏹ توقف سرویس (STOP)", bg=self.danger_color)
            self.status_badge.configure(
                text=f"● در حال اجرا ({cfg['LISTEN_HOST']}:{cfg['LISTEN_PORT']})",
                fg=self.success_color
            )
        except PermissionError:
            self.append_log("[-] دسترسی غیرمجاز: اجرای WinDivert نیازمند Run as Administrator است.")
            messagebox.showerror("نیاز به دسترسی ادمین", "لطفاً برنامه را با Run as Administrator اجرا کنید.")
        except Exception as e:
            self.append_log(f"[-] خطا در راه‌اندازی سرویس: {e}")
            messagebox.showerror("خطای راه‌اندازی", str(e))

    def _stop_service(self):
        if self.engine:
            self.engine.stop()
        self.btn_toggle.configure(text="▶ شروع سرویس (START)", bg=self.success_color)
        self.status_badge.configure(text="● وضعیت: متوقف", fg=self.danger_color)

    def on_closing(self):
        if self.engine and self.engine.is_running:
            self.engine.stop()
        self.destroy()


def run_gui():
    app = BypassApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()


if __name__ == "__main__":
    run_gui()
