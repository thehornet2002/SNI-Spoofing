import copy
import ctypes
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from typing import Optional

from engine import ProxyEngine, load_config_file, save_config_file, get_base_dir
from tester import (
    generate_strategy_presets,
    test_preset_with_live_engine,
    check_socks_connectivity,
    check_target_ip_alive,
    read_lines_from_file,
    PresetConfig,
    build_bypass_config_from_opts,
)


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def restart_as_admin():
    try:
        project_dir = os.path.dirname(os.path.abspath(__file__))
        script = os.path.join(project_dir, "main.py")
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:] if arg != "--no-elevate"])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            f'"{script}" {params}',
            project_dir,
            1
        )
        if ret > 32:
            sys.exit(0)
    except Exception as e:
        messagebox.showerror("خطا", f"امکان اجرای با دسترسی ادمین میسر نشد: {e}")


class BypassApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SNI Spoofing & TCP DPI Bypass Master (Pro Edition)")
        self.geometry("1060x860")
        self.minsize(940, 760)

        # Dark theme palette
        self.bg_color = "#151619"
        self.fg_color = "#e3e5e8"
        self.card_bg = "#202227"
        self.card_border = "#2e3036"
        self.accent_color = "#5865f2"
        self.success_color = "#3ba55d"
        self.danger_color = "#ed4245"
        self.warning_color = "#faa81a"
        self.selected_row_color = "#2a3b5c"

        self.configure(bg=self.bg_color)

        self.engine: Optional[ProxyEngine] = None
        self.config_data = load_config_file()
        self.presets: list[PresetConfig] = generate_strategy_presets(self.config_data.get("FAKE_SNI", "hcaptcha.com"))
        self.preset_results: dict[int, dict] = {}
        self.ip_sni_results: list[dict] = []
        self.benchmark_thread: Optional[threading.Thread] = None
        self.ip_sni_thread: Optional[threading.Thread] = None
        self.cancel_benchmark = False
        self.cancel_ip_sni = False
        self.active_preset_id: Optional[int] = None
        self.filter_mode = "all"  # 'all', 'success', 'untested', 'failed'

        self._setup_styles()
        self._build_ui()
        self._load_config_into_ui()
        self._populate_presets_table()
        self._update_ip_sni_counts()

    def _setup_styles(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        self.style.configure(".", background=self.bg_color, foreground=self.fg_color, font=("Segoe UI", 9))
        self.style.configure("TLabel", background=self.bg_color, foreground=self.fg_color)
        self.style.configure("Card.TFrame", background=self.card_bg, relief="flat")
        self.style.configure("TNotebook", background=self.bg_color, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=self.card_bg, foreground=self.fg_color, padding=[16, 7], font=("Segoe UI", 9, "bold"))
        self.style.map("TNotebook.Tab", background=[("selected", self.accent_color)], foreground=[("selected", "#ffffff")])

        self.style.configure("TCheckbutton", background=self.card_bg, foreground=self.fg_color, font=("Segoe UI", 9))
        self.style.map("TCheckbutton", background=[("active", self.card_bg)], foreground=[("active", "#ffffff")])

        self.style.configure("TEntry", fieldbackground="#2b2d31", foreground="#ffffff", insertcolor="#ffffff")
        self.style.configure("TSpinbox", fieldbackground="#2b2d31", foreground="#ffffff", insertcolor="#ffffff")
        self.style.configure("TCombobox", fieldbackground="#2b2d31", foreground="#ffffff")
        self.style.configure("TProgressbar", thickness=10, troughcolor="#202225", background=self.accent_color)

        # Treeview (v2rayN Style)
        self.style.configure(
            "Treeview",
            background="#1a1b1f",
            foreground="#e1e2e6",
            fieldbackground="#1a1b1f",
            rowheight=26,
            font=("Segoe UI", 9)
        )
        self.style.configure(
            "Treeview.Heading",
            background="#25272e",
            foreground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            padding=[4, 6]
        )
        self.style.map("Treeview", background=[("selected", self.selected_row_color)], foreground=[("selected", "#ffffff")])

    def _build_ui(self):
        # Admin banner if not running as admin
        if not is_admin():
            admin_banner = tk.Frame(self, bg=self.warning_color, padx=10, pady=4)
            admin_banner.pack(fill="x", side="top")
            lbl = tk.Label(
                admin_banner,
                text="⚠️ اجرا بدون دسترسی Administrator. برای کارکرد کامل WinDivert، اجرا با ادمین پیشنهاد می‌شود.",
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

        # Header Frame
        header_frame = tk.Frame(self, bg=self.bg_color, padx=15, pady=6)
        header_frame.pack(fill="x")

        title_lbl = tk.Label(
            header_frame,
            text="⚡ SNI Spoofing & TCP Bypass Master",
            bg=self.bg_color,
            fg="#ffffff",
            font=("Segoe UI", 12, "bold")
        )
        title_lbl.pack(side="left")

        self.status_badge = tk.Label(
            header_frame,
            text="● وضعیت: متوقف",
            bg=self.card_bg,
            fg=self.danger_color,
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=4,
            relief="solid",
            bd=1
        )
        self.status_badge.pack(side="right")

        # Top Control / Target Settings Card
        top_card = tk.LabelFrame(
            self,
            text=" تنظیمات سرور و درگاه v2rayN ",
            bg=self.card_bg,
            fg=self.accent_color,
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=5
        )
        top_card.pack(fill="x", padx=15, pady=(0, 4))

        tk.Label(top_card, text="Target IP:", bg=self.card_bg, fg=self.fg_color).grid(row=0, column=0, sticky="w", padx=3, pady=2)
        self.ent_connect_ip = ttk.Entry(top_card, width=15)
        self.ent_connect_ip.grid(row=0, column=1, sticky="w", padx=(2, 4), pady=2)

        btn_chk_ip = tk.Button(
            top_card, text="🔍 تست IP", command=self.test_target_ip_health,
            bg="#2b2d31", fg=self.fg_color, relief="flat", padx=6, font=("Segoe UI", 8), cursor="hand2"
        )
        btn_chk_ip.grid(row=0, column=2, padx=(0, 10), pady=2)

        tk.Label(top_card, text="Target Port:", bg=self.card_bg, fg=self.fg_color).grid(row=0, column=3, sticky="w", padx=3, pady=2)
        self.ent_connect_port = ttk.Entry(top_card, width=7)
        self.ent_connect_port.grid(row=0, column=4, sticky="w", padx=(2, 10), pady=2)

        tk.Label(top_card, text="Fake SNI:", bg=self.card_bg, fg=self.fg_color).grid(row=0, column=5, sticky="w", padx=3, pady=2)
        self.ent_fake_sni = ttk.Entry(top_card, width=18)
        self.ent_fake_sni.grid(row=0, column=6, sticky="w", padx=(2, 10), pady=2)

        tk.Label(top_card, text="v2rayN SOCKS5:", bg=self.card_bg, fg=self.warning_color, font=("Segoe UI", 9, "bold")).grid(row=0, column=7, sticky="w", padx=3, pady=2)
        self.ent_socks_addr = ttk.Entry(top_card, width=15)
        self.ent_socks_addr.insert(0, "127.0.0.1:10808")
        self.ent_socks_addr.grid(row=0, column=8, sticky="w", padx=(2, 4), pady=2)

        # Tab Notebook
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=4)

        # Tab 1: Strategy Presets (Sequence x Fake HTTP x Fake RST)
        self.tab_bench = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.tab_bench, text="  ⚡ ترکیب Sequence + Fake HTTP + Fake RST  ")
        self._build_benchmark_tab(self.tab_bench)

        # Tab 2: IP & SNI File Matrix Tester (Original SNI Spoofing)
        self.tab_ipsni = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.tab_ipsni, text="  📁 تستر فایل‌های IP و SNI (روش اولیه پروژه)  ")
        self._build_ip_sni_tab(self.tab_ipsni)

        # Tab 3: Manual Tuning & Live Log
        self.tab_manual = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.tab_manual, text="  🛠️ تنظیمات دستی و لاگ زنده  ")
        self._build_manual_tab(self.tab_manual)

    # ================= TAB 1: STRATEGY BENCHMARK =================
    def _build_benchmark_tab(self, parent):
        toolbar = tk.Frame(parent, bg=self.bg_color, pady=4)
        toolbar.pack(fill="x")

        self.btn_quick_test = tk.Button(
            toolbar,
            text="⚡ تست سریع (Quick Check)",
            command=lambda: self.start_benchmark("quick"),
            bg="#216e39",
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=6,
            cursor="hand2"
        )
        self.btn_quick_test.pack(side="left", padx=(0, 5))

        self.btn_ping_test = tk.Button(
            toolbar,
            text="⚡ تست پینگ (Google x4)",
            command=lambda: self.start_benchmark("ping"),
            bg="#2b3d63",
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=6,
            cursor="hand2"
        )
        self.btn_ping_test.pack(side="left", padx=5)

        self.btn_speed_test = tk.Button(
            toolbar,
            text="🚀 تست سرعت (Google x4)",
            command=lambda: self.start_benchmark("speed"),
            bg="#3b5998",
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=6,
            cursor="hand2"
        )
        self.btn_speed_test.pack(side="left", padx=5)

        self.btn_stop_test = tk.Button(
            toolbar,
            text="⏹ لغو تست",
            command=self.stop_benchmark,
            bg="#333338",
            fg=self.fg_color,
            font=("Segoe UI", 9),
            relief="flat",
            padx=10,
            pady=6,
            state="disabled",
            cursor="hand2"
        )
        self.btn_stop_test.pack(side="left", padx=5)

        self.btn_apply_selected = tk.Button(
            toolbar,
            text="✔ اعمال و شروع سرویس (Apply & Start)",
            command=self.apply_selected_preset,
            bg=self.success_color,
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2"
        )
        self.btn_apply_selected.pack(side="right")

        # Filter & Search & Selector Row
        filter_frame = tk.Frame(parent, bg=self.bg_color, pady=4)
        filter_frame.pack(fill="x")

        tk.Label(filter_frame, text="فیلتر نمایش:", bg=self.bg_color, fg=self.fg_color).pack(side="left", padx=(0, 4))
        self.cmb_filter = ttk.Combobox(
            filter_frame,
            values=["همه حالات", "فقط حالات موفق / متصل", "تست نشده‌ها", "ناموفق‌ها / قطع"],
            width=21,
            state="readonly"
        )
        self.cmb_filter.current(0)
        self.cmb_filter.pack(side="left", padx=(0, 10))
        self.cmb_filter.bind("<<ComboboxSelected>>", lambda e: self.on_filter_changed())

        self.var_test_only_filtered = tk.BooleanVar(value=False)
        chk_only_filtered = ttk.Checkbutton(
            filter_frame,
            text="تست فقط روی موارد فیلترشده / متصل",
            variable=self.var_test_only_filtered
        )
        chk_only_filtered.pack(side="left", padx=(0, 12))

        tk.Label(filter_frame, text="🔍 جستجو:", bg=self.bg_color, fg=self.fg_color).pack(side="left", padx=(0, 4))
        self.ent_search = ttk.Entry(filter_frame, width=18)
        self.ent_search.pack(side="left", padx=(0, 10))
        self.ent_search.bind("<KeyRelease>", lambda e: self.filter_presets_table())

        btn_sort_ping = tk.Button(
            filter_frame,
            text="🔽 کمترین پینگ",
            command=lambda: self.sort_table_by("ping_num", reverse=False),
            bg="#23252a",
            fg="#cccccc",
            relief="flat",
            font=("Segoe UI", 8),
            cursor="hand2"
        )
        btn_sort_ping.pack(side="left", padx=3)

        btn_sort_speed = tk.Button(
            filter_frame,
            text="🔽 بیشترین سرعت",
            command=lambda: self.sort_table_by("speed_num", reverse=True),
            bg="#23252a",
            fg="#cccccc",
            relief="flat",
            font=("Segoe UI", 8),
            cursor="hand2"
        )
        btn_sort_speed.pack(side="left", padx=3)

        prog_frame = tk.Frame(parent, bg=self.bg_color, pady=2)
        prog_frame.pack(fill="x")

        self.prog_bar = ttk.Progressbar(prog_frame, mode="determinate")
        self.prog_bar.pack(fill="x", side="left", expand=True, padx=(0, 10))

        self.lbl_bench_status = tk.Label(
            prog_frame,
            text=f"{len(self.presets)} حالت ترکیبی (بدون TTL) | ابتدا «تست سریع» بزنید، سپس روی متصل‌ها پینگ بگیرید",
            bg=self.bg_color,
            fg="#9ba0a8",
            font=("Segoe UI", 8)
        )
        self.lbl_bench_status.pack(side="right")

        table_frame = tk.Frame(parent, bg=self.bg_color)
        table_frame.pack(fill="both", expand=True, pady=(2, 0))

        columns = ("id", "name", "offset", "http", "rst", "driver", "ping", "speed", "status")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("id", text="#", anchor="center", command=lambda: self.sort_table_by("id", reverse=False))
        self.tree.heading("name", text="نام استراتژی / حالت (Bypass Strategy)", anchor="w")
        self.tree.heading("offset", text="Seq Offset", anchor="center")
        self.tree.heading("http", text="Fake HTTP", anchor="center")
        self.tree.heading("rst", text="Fake RST", anchor="center")
        self.tree.heading("driver", text="درایور", anchor="center")
        self.tree.heading("ping", text="تأخیر Google (Ping)", anchor="center", command=lambda: self.sort_table_by("ping_num", reverse=False))
        self.tree.heading("speed", text="سرعت دانلود (Speed)", anchor="center", command=lambda: self.sort_table_by("speed_num", reverse=True))
        self.tree.heading("status", text="وضعیت (Status)", anchor="center", command=lambda: self.sort_table_by("success", reverse=True))

        self.tree.column("id", width=45, anchor="center")
        self.tree.column("name", width=300, anchor="w")
        self.tree.column("offset", width=110, anchor="center")
        self.tree.column("http", width=95, anchor="center")
        self.tree.column("rst", width=85, anchor="center")
        self.tree.column("driver", width=85, anchor="center")
        self.tree.column("ping", width=145, anchor="center")
        self.tree.column("speed", width=110, anchor="center")
        self.tree.column("status", width=90, anchor="center")

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", lambda event: self.apply_selected_preset())

        self.tree.tag_configure("success", foreground="#3ba55d")
        self.tree.tag_configure("partial", foreground="#faa81a")
        self.tree.tag_configure("fail", foreground="#72767d")
        self.tree.tag_configure("testing", foreground="#5865f2")
        self.tree.tag_configure("active", background="#1e3a29", foreground="#57f287")

    # ================= TAB 2: IP & SNI FILE MATRIX TESTER =================
    def _build_ip_sni_tab(self, parent):
        # File selector card
        file_card = tk.LabelFrame(
            parent,
            text=" انتخاب فایل‌های لیست آی‌پی و دامنه‌ها (ips.txt و snis.txt) ",
            bg=self.card_bg,
            fg=self.accent_color,
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=8
        )
        file_card.pack(fill="x", padx=8, pady=6)

        # Row 1: IPs file
        tk.Label(file_card, text="فایل آی‌پی‌ها (IPs file):", bg=self.card_bg, fg=self.fg_color).grid(row=0, column=0, sticky="w", padx=4, pady=3)
        self.ent_ips_file = ttk.Entry(file_card, width=42)
        default_ips = os.path.join(get_base_dir(), "ips.txt")
        self.ent_ips_file.insert(0, default_ips)
        self.ent_ips_file.grid(row=0, column=1, sticky="w", padx=5, pady=3)

        btn_browse_ips = tk.Button(
            file_card, text="انتخاب...", command=self.browse_ips_file,
            bg="#2b2d31", fg=self.fg_color, relief="flat", padx=8, cursor="hand2"
        )
        btn_browse_ips.grid(row=0, column=2, padx=4, pady=3)

        btn_open_ips = tk.Button(
            file_card, text="ویرایش فایل", command=lambda: self.open_file_in_notepad(self.ent_ips_file.get()),
            bg="#2b2d31", fg=self.fg_color, relief="flat", padx=8, cursor="hand2"
        )
        btn_open_ips.grid(row=0, column=3, padx=4, pady=3)

        # Row 2: SNIs file
        tk.Label(file_card, text="فایل دامنه‌ها (SNIs file):", bg=self.card_bg, fg=self.fg_color).grid(row=1, column=0, sticky="w", padx=4, pady=3)
        self.ent_snis_file = ttk.Entry(file_card, width=42)
        default_snis = os.path.join(get_base_dir(), "snis.txt")
        self.ent_snis_file.insert(0, default_snis)
        self.ent_snis_file.grid(row=1, column=1, sticky="w", padx=5, pady=3)

        btn_browse_snis = tk.Button(
            file_card, text="انتخاب...", command=self.browse_snis_file,
            bg="#2b2d31", fg=self.fg_color, relief="flat", padx=8, cursor="hand2"
        )
        btn_browse_snis.grid(row=1, column=2, padx=4, pady=3)

        btn_open_snis = tk.Button(
            file_card, text="ویرایش فایل", command=lambda: self.open_file_in_notepad(self.ent_snis_file.get()),
            bg="#2b2d31", fg=self.fg_color, relief="flat", padx=8, cursor="hand2"
        )
        btn_open_snis.grid(row=1, column=3, padx=4, pady=3)

        btn_refresh_counts = tk.Button(
            file_card, text="🔄 بازخوانی تعداد", command=self._update_ip_sni_counts,
            bg="#2b2d31", fg=self.fg_color, relief="flat", padx=10, cursor="hand2"
        )
        btn_refresh_counts.grid(row=1, column=4, padx=8, pady=3)

        self.lbl_matrix_counts = tk.Label(
            file_card, text="۰ آی‌پی × ۰ دامنه = ۰ حالت",
            bg=self.card_bg, fg=self.warning_color, font=("Segoe UI", 9, "bold")
        )
        self.lbl_matrix_counts.grid(row=0, column=4, padx=8, pady=3)

        # IP x SNI Toolbar
        tb = tk.Frame(parent, bg=self.bg_color, pady=4)
        tb.pack(fill="x", padx=8)

        self.btn_run_ip_sni = tk.Button(
            tb,
            text="⚡ شروع تست ماتریس IP x SNI (روش اولیه پروژه)",
            command=self.start_ip_sni_test,
            bg=self.success_color,
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2"
        )
        self.btn_run_ip_sni.pack(side="left", padx=(0, 6))

        self.btn_stop_ip_sni = tk.Button(
            tb,
            text="⏹ لغو تست",
            command=self.stop_ip_sni_test,
            bg="#333338",
            fg=self.fg_color,
            font=("Segoe UI", 9),
            relief="flat",
            padx=10,
            pady=6,
            state="disabled",
            cursor="hand2"
        )
        self.btn_stop_ip_sni.pack(side="left", padx=6)

        btn_apply_ip_sni = tk.Button(
            tb,
            text="✔ تنظیم این IP و SNI برای اتصال اصلی",
            command=self.apply_selected_ip_sni,
            bg=self.accent_color,
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=6,
            cursor="hand2"
        )
        btn_apply_ip_sni.pack(side="right")

        # IP x SNI Progress
        p_frame = tk.Frame(parent, bg=self.bg_color, pady=2)
        p_frame.pack(fill="x", padx=8)

        self.prog_ip_sni = ttk.Progressbar(p_frame, mode="determinate")
        self.prog_ip_sni.pack(fill="x", side="left", expand=True, padx=(0, 10))

        self.lbl_ip_sni_status = tk.Label(
            p_frame, text="آماده تست | دابل‌کلیک روی ردیف موفق = اعمال فوری IP و SNI",
            bg=self.bg_color, fg="#9ba0a8", font=("Segoe UI", 8)
        )
        self.lbl_ip_sni_status.pack(side="right")

        # IP x SNI Table
        tbl_frame = tk.Frame(parent, bg=self.bg_color)
        tbl_frame.pack(fill="both", expand=True, padx=8, pady=(2, 6))

        ip_columns = ("id", "ip", "sni", "ping", "status")
        self.tree_ipsni = ttk.Treeview(tbl_frame, columns=ip_columns, show="headings", selectmode="browse")

        self.tree_ipsni.heading("id", text="#", anchor="center")
        self.tree_ipsni.heading("ip", text="Target IP (سرور / CDN)", anchor="center")
        self.tree_ipsni.heading("sni", text="Fake SNI (دامنه مجاز)", anchor="w")
        self.tree_ipsni.heading("ping", text="تأخیر پاسخ (Ping)", anchor="center")
        self.tree_ipsni.heading("status", text="وضعیت اتصال", anchor="center")

        self.tree_ipsni.column("id", width=45, anchor="center")
        self.tree_ipsni.column("ip", width=220, anchor="center")
        self.tree_ipsni.column("sni", width=340, anchor="w")
        self.tree_ipsni.column("ping", width=160, anchor="center")
        self.tree_ipsni.column("status", width=120, anchor="center")

        scroll_ip = ttk.Scrollbar(tbl_frame, orient="vertical", command=self.tree_ipsni.yview)
        self.tree_ipsni.configure(yscrollcommand=scroll_ip.set)

        self.tree_ipsni.pack(side="left", fill="both", expand=True)
        scroll_ip.pack(side="right", fill="y")

        self.tree_ipsni.bind("<Double-1>", lambda e: self.apply_selected_ip_sni())

        self.tree_ipsni.tag_configure("success", foreground="#3ba55d")
        self.tree_ipsni.tag_configure("fail", foreground="#72767d")
        self.tree_ipsni.tag_configure("testing", foreground="#5865f2")

    # ================= TAB 3: MANUAL TUNING & LOG =================
    def _build_manual_tab(self, parent):
        strat_card = tk.LabelFrame(
            parent,
            text=" تنظیمات دستی استراتژی‌ها (Manual Bypass Options) ",
            bg=self.card_bg,
            fg=self.accent_color,
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=8
        )
        strat_card.pack(fill="x", padx=8, pady=6)

        self.var_wrong_seq = tk.BooleanVar(value=True)
        self.var_fake_rst = tk.BooleanVar(value=False)
        self.var_fake_http = tk.StringVar(value="none")
        self.var_seq_offset_type = tk.StringVar(value="classic")
        self.var_use_npcap = tk.BooleanVar(value=True)

        col1 = tk.Frame(strat_card, bg=self.card_bg)
        col1.pack(side="left", fill="both", expand=True, padx=5)

        ttk.Checkbutton(col1, text="Wrong Seq (بای‌پس اصلی با شماره توالی ناهماهنگ)", variable=self.var_wrong_seq).pack(anchor="w", pady=3)
        ttk.Checkbutton(col1, text="Fake RST State Poisoning (تزریق RST فیک)", variable=self.var_fake_rst).pack(anchor="w", pady=3)
        ttk.Checkbutton(col1, text="Direct NIC via Npcap (تزریق مستقیم به درایور کارت شبکه)", variable=self.var_use_npcap).pack(anchor="w", pady=3)

        col2 = tk.Frame(strat_card, bg=self.card_bg)
        col2.pack(side="left", fill="both", expand=True, padx=5)

        http_f = tk.Frame(col2, bg=self.card_bg)
        http_f.pack(anchor="w", fill="x", pady=3)
        tk.Label(http_f, text="Fake HTTP Probe:", bg=self.card_bg, fg=self.fg_color).pack(side="left")
        ttk.Combobox(http_f, textvariable=self.var_fake_http, values=["none", "get", "head"], width=10, state="readonly").pack(side="left", padx=5)

        off_f = tk.Frame(col2, bg=self.card_bg)
        off_f.pack(anchor="w", fill="x", pady=3)
        tk.Label(off_f, text="Seq Offset Type:", bg=self.card_bg, fg=self.fg_color).pack(side="left")
        ttk.Combobox(off_f, textvariable=self.var_seq_offset_type, values=["classic", "offset", "abs"], width=10, state="readonly").pack(side="left", padx=5)

        ctrl_bar = tk.Frame(parent, bg=self.bg_color, pady=4)
        ctrl_bar.pack(fill="x", padx=8)

        self.btn_toggle_service = tk.Button(
            ctrl_bar,
            text="▶ شروع سرویس (START)",
            command=self.toggle_service,
            bg=self.success_color,
            fg="#ffffff",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=20,
            pady=6,
            cursor="hand2"
        )
        self.btn_toggle_service.pack(side="left", padx=(0, 8))

        btn_save = tk.Button(
            ctrl_bar,
            text="ذخیره تنظیمات دستی",
            command=self.save_manual_settings,
            bg="#2b2d31",
            fg=self.fg_color,
            font=("Segoe UI", 9),
            relief="flat",
            padx=12,
            pady=6,
            cursor="hand2"
        )
        btn_save.pack(side="left", padx=4)

        btn_clear = tk.Button(
            ctrl_bar,
            text="پاک کردن لاگ",
            command=self.clear_logs,
            bg="#2b2d31",
            fg=self.fg_color,
            font=("Segoe UI", 9),
            relief="flat",
            padx=10,
            pady=6,
            cursor="hand2"
        )
        btn_clear.pack(side="right")

        log_card = tk.LabelFrame(
            parent,
            text=" رویدادها و لاگ زنده (Live Events) ",
            bg=self.card_bg,
            fg=self.accent_color,
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=6
        )
        log_card.pack(fill="both", expand=True, padx=8, pady=(4, 6))

        self.txt_log = scrolledtext.ScrolledText(
            log_card,
            bg="#111214",
            fg="#cccccc",
            insertbackground="#ffffff",
            font=("Consolas", 9),
            relief="flat",
            wrap="word",
            state="disabled"
        )
        self.txt_log.pack(fill="both", expand=True)

        self.txt_log.tag_config("info", foreground="#5865f2")
        self.txt_log.tag_config("success", foreground="#3ba55d")
        self.txt_log.tag_config("warning", foreground="#faa81a")
        self.txt_log.tag_config("error", foreground="#ed4245")

    # ================= LOGIC: FILE HELPERS =================
    def browse_ips_file(self):
        f = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if f:
            self.ent_ips_file.delete(0, tk.END)
            self.ent_ips_file.insert(0, f)
            self._update_ip_sni_counts()

    def browse_snis_file(self):
        f = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if f:
            self.ent_snis_file.delete(0, tk.END)
            self.ent_snis_file.insert(0, f)
            self._update_ip_sni_counts()

    def open_file_in_notepad(self, file_path: str):
        if not os.path.exists(file_path):
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    pass
            except Exception:
                pass
        try:
            os.system(f'notepad.exe "{file_path}"')
        except Exception as e:
            messagebox.showerror("خطا", str(e))

    def _update_ip_sni_counts(self):
        ips = read_lines_from_file(self.ent_ips_file.get())
        snis = read_lines_from_file(self.ent_snis_file.get())
        total = len(ips) * len(snis)
        self.lbl_matrix_counts.configure(text=f"{len(ips)} آی‌پی × {len(snis)} دامنه = {total} حالت")

    # ================= LOGIC: IP x SNI TESTING =================
    def start_ip_sni_test(self):
        socks_addr = self.ent_socks_addr.get().strip()
        ok, err_msg = check_socks_connectivity(socks_addr)
        if not ok:
            messagebox.showerror("خطای SOCKS5", f"امکان اتصال به {socks_addr} وجود ندارد:\n{err_msg}")
            return

        ips = read_lines_from_file(self.ent_ips_file.get())
        snis = read_lines_from_file(self.ent_snis_file.get())
        if not ips or not snis:
            messagebox.showwarning("توجه", "لطفاً ابتدا فایل‌های ips.txt و snis.txt را با حداقل یک آی‌پی و دامنه پر کنید.")
            return

        self.btn_run_ip_sni.configure(state="disabled")
        self.btn_stop_ip_sni.configure(state="normal")
        self.cancel_ip_sni = False

        pairs = []
        for ip in ips:
            for sni in snis:
                pairs.append((ip, sni))

        self.tree_ipsni.delete(*self.tree_ipsni.get_children())
        for idx, (ip, sni) in enumerate(pairs, 1):
            self.tree_ipsni.insert("", "end", iid=str(idx), values=(idx, ip, sni, "-", "در صف تست"), tags=("fail",))

        self.prog_ip_sni["maximum"] = len(pairs)
        self.prog_ip_sni["value"] = 0

        self.ip_sni_thread = threading.Thread(
            target=self._run_ip_sni_worker,
            args=(pairs, socks_addr),
            daemon=True
        )
        self.ip_sni_thread.start()

    def _run_ip_sni_worker(self, pairs: list[tuple[str, str]], socks_addr: str):
        total = len(pairs)
        success_cnt = 0
        current_ip = None

        for idx, (ip, sni) in enumerate(pairs, 1):
            if self.cancel_ip_sni:
                break

            def _mark_test(i=idx, ip_t=ip, sni_t=sni):
                if self.tree_ipsni.exists(str(i)):
                    self.tree_ipsni.item(str(i), tags=("testing",), values=(i, ip_t, sni_t, "...", "در حال تست"))
                self.lbl_ip_sni_status.configure(text=f"در حال تست {i}/{total}: {ip_t} | {sni_t}")
                self.prog_ip_sni["value"] = i

            self.after(0, _mark_test)

            # If IP changed, restart engine with new CONNECT_IP
            if current_ip != ip:
                current_ip = ip
                if self.engine:
                    self.engine.stop()

                cfg = self.get_current_base_config()
                cfg["CONNECT_IP"] = ip
                cfg["FAKE_SNI"] = sni
                cfg["BYPASS_OPTIONS"]["wrong_seq"] = True
                cfg["BYPASS_OPTIONS"]["seq_offset_type"] = "classic"
                cfg["BYPASS_OPTIONS"]["use_npcap"] = True
                self.engine = ProxyEngine(cfg)
                self.engine.start()
                self.engine.wait_until_ready(timeout=2.5)
            else:
                self.engine.fake_sni = sni
                self.engine.bypass_config.fake_sni = sni
                time.sleep(0.05)

            # Test using curl with 6s timeout
            socks_url = f"socks5h://{socks_addr}"
            t0 = time.time()
            success = False
            dt = 0
            try:
                res = subprocess.run(
                    ["curl.exe", "-s", "-k", "-L", "-o", "NUL", "-w", "%{http_code}", "-m", "6", "-x", socks_url, "https://www.google.com"],
                    capture_output=True, text=True, timeout=7, creationflags=0x08000000
                )
                dt = int((time.time() - t0) * 1000)
                code = res.stdout.strip()
                if code in ("200", "301", "302", "204") or (code.isdigit() and 200 <= int(code) < 400):
                    success = True
            except Exception:
                pass

            if success:
                success_cnt += 1
                ping_str = f"{dt} ms"
                st_str = "متصل"
                tag = "success"
                self.append_log(f"[✓] IP: {ip} | SNI: {sni} -> متصل ({dt}ms)")
            else:
                ping_str = "Timeout"
                st_str = "قطع"
                tag = "fail"

            def _update_row(i=idx, ip_t=ip, sni_t=sni, p_s=ping_str, s_s=st_str, tg=tag):
                if self.tree_ipsni.exists(str(i)):
                    self.tree_ipsni.item(str(i), values=(i, ip_t, sni_t, p_s, s_s), tags=(tg,))

            self.after(0, _update_row)
            time.sleep(0.04)

        def _finish():
            self.btn_run_ip_sni.configure(state="normal")
            self.btn_stop_ip_sni.configure(state="disabled")
            msg = f"پایان تست: {success_cnt} حالت از {total} موفق بودند."
            if self.cancel_ip_sni:
                msg = f"تست متوقف شد. ({success_cnt} موفق)"
            self.lbl_ip_sni_status.configure(text=msg)
            self.append_log(f"[*] {msg}")

        self.after(0, _finish)

    def stop_ip_sni_test(self):
        self.cancel_ip_sni = True
        self.lbl_ip_sni_status.configure(text="در حال لغو تست...")
        self.btn_stop_ip_sni.configure(state="disabled")

    def apply_selected_ip_sni(self):
        sel = self.tree_ipsni.selection()
        if not sel:
            messagebox.showinfo("انتخاب", "لطفاً یک ردیف را انتخاب کنید.")
            return

        item = self.tree_ipsni.item(sel[0])
        vals = item["values"]
        selected_ip = str(vals[1])
        selected_sni = str(vals[2])

        self.ent_connect_ip.delete(0, tk.END)
        self.ent_connect_ip.insert(0, selected_ip)

        self.ent_fake_sni.delete(0, tk.END)
        self.ent_fake_sni.insert(0, selected_sni)

        cfg = self.get_current_base_config()
        cfg["CONNECT_IP"] = selected_ip
        cfg["FAKE_SNI"] = selected_sni
        save_config_file(cfg)

        self.append_log(f"[✓] تنظیمات با Target IP: {selected_ip} و Fake SNI: {selected_sni} ذخیره و فعال شد.")
        self._start_service()
        messagebox.showinfo("موفقیت", f"سرویس با IP: {selected_ip} و SNI: {selected_sni} استارت شد.")

    # ================= LOGIC: TAB 1 STRATEGY PRESETS =================
    def on_filter_changed(self):
        sel = self.cmb_filter.get()
        if "موفق" in sel:
            self.filter_mode = "success"
        elif "تست نشده" in sel:
            self.filter_mode = "untested"
        elif "ناموفق" in sel:
            self.filter_mode = "failed"
        else:
            self.filter_mode = "all"
        self._populate_presets_table()

    def get_displayed_presets(self) -> list[PresetConfig]:
        query = self.ent_search.get().strip().lower() if hasattr(self, "ent_search") else ""
        filtered = []

        for p in self.presets:
            res = self.preset_results.get(p.id)
            if self.filter_mode == "success" and (not res or not res.get("success")):
                continue
            elif self.filter_mode == "untested" and res is not None:
                continue
            elif self.filter_mode == "failed" and (not res or res.get("success")):
                continue

            if query:
                text_to_match = f"{p.name} {p.offset_label} {p.http_label} {p.rst_label} {p.driver_label}".lower()
                if query not in text_to_match:
                    continue

            filtered.append(p)
        return filtered

    def _populate_presets_table(self):
        self.tree.delete(*self.tree.get_children())
        displayed = self.get_displayed_presets()

        for p in displayed:
            res = self.preset_results.get(p.id)
            if res:
                ping_str = res.get("ping", "-")
                speed_str = res.get("speed", "-")
                status_str = res.get("status", "تست نشده")
                tag = "success" if res.get("success") and ("4/4" in res.get("ratio", "") or "1/1" in res.get("ratio", "")) else ("partial" if res.get("success") else "fail")
            else:
                ping_str = "-"
                speed_str = "-"
                status_str = "تست نشده"
                tag = "fail"

            if self.active_preset_id == p.id:
                tag = "active"

            self.tree.insert(
                "",
                "end",
                iid=str(p.id),
                values=(p.id, p.name, p.offset_label, p.http_label, p.rst_label, p.driver_label, ping_str, speed_str, status_str),
                tags=(tag,)
            )

    def filter_presets_table(self):
        self._populate_presets_table()

    def sort_table_by(self, key: str, reverse: bool = False):
        def _get_sort_val(p: PresetConfig):
            res = self.preset_results.get(p.id)
            if key == "id":
                return p.id
            elif key == "success":
                return 1 if (res and res.get("success")) else 0
            if not res or not res.get("success"):
                return 9999999 if not reverse else -1
            return res.get(key, 9999999 if not reverse else -1)

        self.presets.sort(key=_get_sort_val, reverse=reverse)
        self._populate_presets_table()

    def _load_config_into_ui(self):
        c = self.config_data
        self.ent_connect_ip.delete(0, tk.END)
        self.ent_connect_ip.insert(0, c.get("CONNECT_IP", "172.67.173.69"))

        self.ent_connect_port.delete(0, tk.END)
        self.ent_connect_port.insert(0, str(c.get("CONNECT_PORT", 443)))

        self.ent_fake_sni.delete(0, tk.END)
        self.ent_fake_sni.insert(0, c.get("FAKE_SNI", "hcaptcha.com"))

        opts = c.get("BYPASS_OPTIONS", {})
        self.var_wrong_seq.set(opts.get("wrong_seq", True))
        self.var_fake_rst.set(opts.get("fake_rst", False))
        self.var_fake_http.set(opts.get("fake_http", "none"))
        self.var_seq_offset_type.set(opts.get("seq_offset_type", "classic"))
        self.var_use_npcap.set(opts.get("use_npcap", True))

    def get_current_base_config(self) -> dict:
        return {
            "LISTEN_HOST": "0.0.0.0",
            "LISTEN_PORT": 40443,
            "CONNECT_IP": self.ent_connect_ip.get().strip(),
            "CONNECT_PORT": int(self.ent_connect_port.get().strip()),
            "FAKE_SNI": self.ent_fake_sni.get().strip(),
            "BYPASS_OPTIONS": {
                "wrong_seq": self.var_wrong_seq.get(),
                "seq_offset_type": self.var_seq_offset_type.get(),
                "seq_offset_val": -1,
                "fake_http": self.var_fake_http.get(),
                "fake_rst": self.var_fake_rst.get(),
                "use_npcap": self.var_use_npcap.get(),
            }
        }

    def test_target_ip_health(self):
        target_ip = self.ent_connect_ip.get().strip()
        target_port = int(self.ent_connect_port.get().strip() or "443")
        ok, msg = check_target_ip_alive(target_ip, target_port)
        if ok:
            messagebox.showinfo(
                "نتیجه تست سلامت IP",
                f"آی‌پی {target_ip}:{target_port} کاملاً سالم و در دسترس است.\nزمان پاسخگویی TCP: {msg}"
            )
        else:
            messagebox.showerror(
                "خطا: آی‌پی هدف قطع است!",
                f"آی‌پی انتخابی ({target_ip}) به پورت {target_port} پاسخ نمی‌دهد!\nخطا: {msg}\n\n"
                f"علت: این آی‌پی در شبکه شما فیلتر، قطع یا تایم‌اوت است.\n\n"
                f"راه‌حل: لطفاً از آی‌پی‌های سالم کلودفلر استفاده کنید:\n"
                f"• آی‌پی فعال دامنه شما: 172.67.173.69 یا 104.21.96.50\n"
                f"• آی‌پی‌های تمیز عمومی: 188.114.98.0 یا 104.16.132.229\n"
                f"(همچنین در تب دوم می‌توانید تمام آی‌پی‌ها را با یک کلیک تست کنید)"
            )

    def start_benchmark(self, test_type: str):
        target_ip = self.ent_connect_ip.get().strip()
        target_port = int(self.ent_connect_port.get().strip() or "443")

        # 0. Check if target IP is alive
        ip_alive, ip_err = check_target_ip_alive(target_ip, target_port, timeout=2.0)
        if not ip_alive:
            messagebox.showerror(
                "آی‌پی هدف (Target IP) قطع است!",
                f"آی‌پی {target_ip} به پورت {target_port} پاسخ نمی‌دهد (تایم‌اوت لایه TCP)!\n\n"
                f"به همین دلیل تمام تست‌ها قطع خواهند شد.\n\n"
                f"لطفاً Target IP را به یکی از آی‌پی‌های سالم زیر تغییر دهید:\n"
                f"• 172.67.173.69 (آی‌پی فعال دامین شما)\n"
                f"• 104.21.96.50\n"
                f"• 188.114.98.0\n\n"
                f"سپس تست را مجدداً شروع کنید."
            )
            return

        socks_addr = self.ent_socks_addr.get().strip()
        ok, err_msg = check_socks_connectivity(socks_addr)
        if not ok:
            messagebox.showerror("خطای SOCKS5", f"امکان اتصال به {socks_addr} وجود ندارد:\n{err_msg}")
            return

        if not self.engine or not self.engine.is_running:
            self._start_service()

        if self.engine and not self.engine.wait_until_ready(timeout=3.0):
            messagebox.showerror("خطا", "پروکسی روی پورت 40443 آماده نشد.")
            return

        current_sni = self.ent_fake_sni.get().strip() or "hcaptcha.com"
        if not self.presets or self.presets[0].options.get("fake_sni") != current_sni:
            self.presets = generate_strategy_presets(current_sni)
            self._populate_presets_table()

        if self.var_test_only_filtered.get():
            target_presets = self.get_displayed_presets()
            if not target_presets:
                messagebox.showinfo("اطلاع", "هیچ موردی مطابق فیلتر فعلی وجود ندارد.")
                return
        else:
            target_presets = self.presets

        self.btn_quick_test.configure(state="disabled")
        self.btn_ping_test.configure(state="disabled")
        self.btn_speed_test.configure(state="disabled")
        self.btn_stop_test.configure(state="normal")
        self.cancel_benchmark = False

        self.prog_bar["maximum"] = len(target_presets)
        self.prog_bar["value"] = 0

        mode_titles = {
            "quick": "تست سریع اتصال (Quick)",
            "ping": "تست پینگ Google (x4)",
            "speed": "تست سرعت Google (x4)"
        }
        mode_title = mode_titles.get(test_type, test_type)

        self.lbl_bench_status.configure(text=f"شروع {mode_title} روی {len(target_presets)} حالت...")
        self.append_log(f"[*] شروع {mode_title} روی {len(target_presets)} حالت از طریق SOCKS5 {socks_addr}...")

        self.benchmark_thread = threading.Thread(
            target=self._run_benchmark_worker,
            args=(target_presets, socks_addr, test_type),
            daemon=True
        )
        self.benchmark_thread.start()

    def _run_benchmark_worker(self, target_presets: list[PresetConfig], socks_addr: str, test_type: str):
        total = len(target_presets)
        successful_count = 0

        for idx, preset in enumerate(target_presets):
            if self.cancel_benchmark:
                break

            def _mark_testing(pid=preset.id, cur=idx + 1):
                if self.tree.exists(str(pid)):
                    self.tree.item(str(pid), tags=("testing",))
                self.lbl_bench_status.configure(text=f"در حال تست {cur}/{total}: {preset.name}")
                self.prog_bar["value"] = cur

            self.after(0, _mark_testing)

            res = test_preset_with_live_engine(
                self.engine,
                preset,
                socks_addr=socks_addr,
                test_type=test_type,
                repeats=4 if test_type != "quick" else 1,
                timeout_per_probe=7 if test_type != "quick" else 6
            )
            self.preset_results[preset.id] = res

            if res["success"]:
                successful_count += 1
                self.append_log(f"[+] #{preset.id} ({preset.name}) -> {res.get('ping', '')} | {res.get('status', '')}")

            def _update_row(r=res):
                tag = "success" if r["success"] and ("4/4" in r.get("ratio", "") or "1/1" in r.get("ratio", "")) else ("partial" if r["success"] else "fail")
                if self.tree.exists(str(r["id"])):
                    self.tree.item(
                        str(r["id"]),
                        values=(r["id"], r["name"], r["offset"], r["http"], r["rst"], r["driver"], r["ping"], r["speed"], r["status"]),
                        tags=(tag,)
                    )

            self.after(0, _update_row)
            time.sleep(0.04)

        def _finish():
            self.btn_quick_test.configure(state="normal")
            self.btn_ping_test.configure(state="normal")
            self.btn_speed_test.configure(state="normal")
            self.btn_stop_test.configure(state="disabled")
            status_msg = f"پایان تست: {successful_count} حالت از {total} موفق بودند."
            if self.cancel_benchmark:
                status_msg = f"تست توسط کاربر متوقف شد. ({successful_count} موفق)"
            self.lbl_bench_status.configure(text=status_msg)
            self.append_log(f"[✓] {status_msg}")

            if test_type == "speed":
                self.sort_table_by("speed_num", reverse=True)
            elif test_type == "ping":
                self.sort_table_by("ping_num", reverse=False)
            elif test_type == "quick":
                self.sort_table_by("success", reverse=True)

        self.after(0, _finish)

    def stop_benchmark(self):
        self.cancel_benchmark = True
        self.lbl_bench_status.configure(text="در حال لغو تست...")
        self.btn_stop_test.configure(state="disabled")

    def apply_selected_preset(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("انتخاب حالت", "لطفاً یک حالت را از جدول انتخاب کنید.")
            return

        preset_id = int(selected[0])
        preset = next((p for p in self.presets if p.id == preset_id), None)
        if not preset:
            return

        self.active_preset_id = preset_id

        opts = copy.deepcopy(preset.options)
        self.var_wrong_seq.set(opts.get("wrong_seq", True))
        self.var_fake_rst.set(opts.get("fake_rst", False))
        self.var_fake_http.set(opts.get("fake_http", "none"))
        self.var_seq_offset_type.set(opts.get("seq_offset_type", "classic"))
        self.var_use_npcap.set(opts.get("use_npcap", True))

        cfg = self.get_current_base_config()
        save_config_file(cfg)
        self.append_log(f"[✓] حالت #{preset.id} ({preset.name}) انتخاب و اعمال شد.")

        if self.engine and self.engine.is_running:
            self.engine.bypass_config = build_bypass_config_from_opts(opts, fallback_sni=self.engine.fake_sni)
            self.status_badge.configure(
                text=f"● در حال اجرا (#{preset.id}: {preset.name[:20]})",
                fg=self.success_color
            )
        else:
            self._start_service()

        self._populate_presets_table()

    # ================= LOGIC: SERVICE START / STOP =================
    def toggle_service(self):
        if self.engine and self.engine.is_running:
            self._stop_service()
        else:
            self._start_service()

    def _start_service(self):
        try:
            if self.engine and self.engine.is_running:
                self.engine.stop()

            cfg = self.get_current_base_config()
            save_config_file(cfg)
            self.engine = ProxyEngine(cfg, log_callback=self.append_log)
            self.engine.start()

            self.btn_toggle_service.configure(text="⏹ توقف سرویس (STOP)", bg=self.danger_color)
            self.status_badge.configure(
                text=f"● در حال اجرا ({cfg['LISTEN_HOST']}:{cfg['LISTEN_PORT']})",
                fg=self.success_color
            )
        except PermissionError:
            self.append_log("[-] دسترسی غیرمجاز: اجرای کامل نیازمند Run as Administrator است.")
            messagebox.showerror("دسترسی ادمین", "لطفاً برنامه را با Run as Administrator اجرا کنید.")
        except Exception as e:
            self.append_log(f"[-] خطا در راه‌اندازی سرویس: {e}")
            messagebox.showerror("خطا", str(e))

    def _stop_service(self):
        if self.engine:
            self.engine.stop()
        self.btn_toggle_service.configure(text="▶ شروع سرویس (START)", bg=self.success_color)
        self.status_badge.configure(text="● وضعیت: متوقف", fg=self.danger_color)

    def save_manual_settings(self):
        try:
            cfg = self.get_current_base_config()
            save_config_file(cfg)
            self.append_log("[✓] تنظیمات با موفقیت در config.json ذخیره شد.")
            messagebox.showinfo("موفقیت", "تنظیمات با موفقیت ذخیره شد.")
        except Exception as e:
            messagebox.showerror("خطا", str(e))

    def append_log(self, text: str):
        def _insert():
            self.txt_log.configure(state="normal")
            tag = "info"
            if "[✓]" in text:
                tag = "success"
            elif "[-]" in text or "خطا" in text:
                tag = "error"
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

    def on_closing(self):
        self.cancel_benchmark = True
        self.cancel_ip_sni = True
        if self.engine and self.engine.is_running:
            self.engine.stop()
        self.destroy()


def run_gui():
    app = BypassApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()


if __name__ == "__main__":
    run_gui()
