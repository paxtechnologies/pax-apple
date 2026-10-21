# SPDX-License-Identifier: GPL-3.0-only
"""The window: a small guided tkinter app in Pax's brand (Mist background, white cards,
Navy text and buttons, Dusk accents; Pax Fraunces Soft and Pax Inter when they load,
Segoe UI otherwise). tkinter ships with CPython, so the app needs nothing else.

Every step that talks to the phone or the server runs on a worker thread; results come
back through a queue the window polls, so the window never freezes."""
from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import font as tkfont
from tkinter import ttk
from typing import Any, Callable, Optional

from . import APP_NAME, VERSION, paths, wording as W
from . import choices as ch
from . import driver as drv
from .account import EmailAccount
from .escrow import EscrowClient
from .flow import Device, SetupFailed, SetupSession, classify
from .helper import DemoHelperRunner, HelperRunner
from .token_store import MemoryTokenStore, default_store

MIST, NAVY, DUSK, HAZE, WHITE, SLATE, WARN = ("#F7F9FB", "#1E2A38", "#6E8BA8", "#C9D4DF",
                                              "#FFFFFF", "#3B4654", "#A5564F")
POLL_MS = 100
SEARCH_EVERY_S = 2.0
WAIT_TOO_LONG_S = 300
WRAP = 530


def _load_brand_fonts() -> None:
    """Private (this process only) load of the OFL fonts the Mac app bundles."""
    if os.name != "nt":
        return
    try:
        import ctypes
        folder = paths.resource("mac-app", "Resources", "fonts")
        for f in folder.glob("*.ttf"):
            ctypes.windll.gdi32.AddFontResourceExW(str(f), 0x10, 0)   # FR_PRIVATE
    except Exception:  # noqa: BLE001  (fonts are a nicety)
        pass


class App:
    def __init__(self, root: tk.Tk, demo: bool = False):
        self.root = root
        self.demo = demo
        self.q: "queue.Queue[tuple[Callable, tuple]]" = queue.Queue()
        server = os.environ.get("PAX_SERVER_URL") or ch.DEFAULT_SERVER
        data = paths.data_dir()
        self.tokens = MemoryTokenStore() if demo else default_store(data, server)
        escrow = EscrowClient(server, token=self.tokens.load())
        runner = DemoHelperRunner() if demo else HelperRunner()
        dns_health = (lambda _b: True) if demo else None
        kwargs: dict[str, Any] = {"on_event": lambda e: self.q.put((self._on_helper_event, (e,)))}
        if dns_health:
            kwargs["dns_health"] = dns_health
        if demo:
            escrow = _DemoEscrow()
        self.session = SetupSession(runner, escrow, data, **kwargs)
        self.choices = ch.SetupChoices()
        if os.environ.get("PAX_DNS_BASE"):
            self.choices.dns_base = os.environ["PAX_DNS_BASE"]
        self.account: Optional[EmailAccount] = None
        self.limits = ch.WaitLimits.standard()
        self.device: Optional[Device] = None
        self.step = 0
        self.busy = False
        self.searching = False
        self.status_text = tk.StringVar(value="")
        self.progress_text = tk.StringVar(value="")
        self.phone_state = ""
        self._setup_style()
        self._build_shell()
        self.show_connect()
        self.root.after(POLL_MS, self._drain)
        if not demo:
            self.run_bg(self.session.escrow.wait_limits, self._got_limits, quiet=True)

    # ------------------------------------------------------------------ plumbing
    def _setup_style(self) -> None:
        _load_brand_fonts()
        fams = set(tkfont.families(self.root))
        body = "Pax Inter" if "Pax Inter" in fams else "Segoe UI"
        head = "Pax Fraunces Soft" if "Pax Fraunces Soft" in fams else ("Georgia" if "Georgia" in fams else body)
        self.f_head = (head, 22)
        self.f_sub = (body, 11)
        self.f_body = (body, 10)
        self.f_small = (body, 9)
        self.f_bold = (body, 11, "bold")
        self.root.configure(bg=MIST)
        st = ttk.Style(self.root)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=MIST, foreground=NAVY, font=self.f_body)
        st.configure("Card.TFrame", background=WHITE, relief="solid", borderwidth=1, bordercolor=HAZE)
        st.configure("Card.TLabel", background=WHITE, foreground=NAVY)
        st.configure("Muted.Card.TLabel", background=WHITE, foreground=SLATE, font=self.f_small)
        st.configure("Card.TCheckbutton", background=WHITE, foreground=NAVY)
        st.configure("Card.TRadiobutton", background=WHITE, foreground=NAVY)
        st.configure("Primary.TButton", background=NAVY, foreground=WHITE, font=self.f_bold,
                     padding=(18, 8), borderwidth=0)
        st.map("Primary.TButton", background=[("disabled", HAZE), ("active", DUSK)],
               foreground=[("disabled", WHITE)])
        st.configure("Secondary.TButton", background=WHITE, foreground=NAVY, padding=(14, 6),
                     bordercolor=HAZE)
        st.configure("Rail.TLabel", background=NAVY, foreground=HAZE, font=self.f_body)
        st.configure("RailOn.TLabel", background=NAVY, foreground=WHITE, font=self.f_bold)

    def _build_shell(self) -> None:
        self.root.title(APP_NAME)
        self.root.geometry("860x660")
        self.root.minsize(760, 600)
        rail = tk.Frame(self.root, bg=NAVY, width=190)
        rail.pack(side="left", fill="y")
        rail.pack_propagate(False)
        self._logo = None
        try:
            img = tk.PhotoImage(file=str(paths.resource("mac-app", "Resources", "branding", "pax-white.png")))
            self._logo = img.subsample(6, 6)
            tk.Label(rail, image=self._logo, bg=NAVY).pack(padx=18, pady=(24, 18), anchor="w")
        except tk.TclError:
            tk.Label(rail, text="pax", fg=WHITE, bg=NAVY, font=(self.f_head[0], 26)).pack(
                padx=18, pady=(24, 18), anchor="w")
        self.rail_labels = []
        for i, t in enumerate(W.STEP_TITLES):
            lab = ttk.Label(rail, text=f"{i + 1}  {t}", style="Rail.TLabel")
            lab.pack(anchor="w", padx=20, pady=6)
            self.rail_labels.append(lab)
        tk.Label(rail, text=f"Version {VERSION}" + ("  \u00b7  demo" if self.demo else ""),
                 fg=HAZE, bg=NAVY, font=self.f_small).pack(side="bottom", anchor="w", padx=20, pady=14)
        # The step content scrolls when it is taller than the window (small laptop screens).
        outer = tk.Frame(self.root, bg=MIST)
        outer.pack(side="left", fill="both", expand=True)
        self.canvas = tk.Canvas(outer, bg=MIST, highlightthickness=0)
        bar = ttk.Scrollbar(outer, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.body = tk.Frame(self.canvas, bg=MIST, padx=34, pady=26)
        self._body_id = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.body.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self._body_id, width=e.width))
        self.root.bind_all("<MouseWheel>", lambda e: self.canvas.yview_scroll(int(-e.delta / 120), "units"))

    def _set_step(self, i: int) -> None:
        self.step = i
        for j, lab in enumerate(self.rail_labels):
            lab.configure(style="RailOn.TLabel" if j == i else "Rail.TLabel")

    def _clear(self) -> None:
        for w in self.body.winfo_children():
            w.destroy()
        self.canvas.yview_moveto(0)

    def _drain(self) -> None:
        try:
            while True:
                fn, args = self.q.get_nowait()
                fn(*args)
        except queue.Empty:
            pass
        self.root.after(POLL_MS, self._drain)

    def run_bg(self, work: Callable[[], Any], done: Callable[[Any], None],
               failed: Optional[Callable[[BaseException], None]] = None, quiet: bool = False) -> None:
        if not quiet:
            self.busy = True

        def target():
            try:
                result = work()
            except BaseException as exc:  # noqa: BLE001
                self.q.put((self._failed, (exc, failed, quiet)))
                return
            self.q.put((self._done, (done, result, quiet)))
        threading.Thread(target=target, daemon=True).start()

    def _done(self, done, result, quiet) -> None:
        if not quiet:
            self.busy = False
        done(result)

    def _failed(self, exc, failed, quiet) -> None:
        if not quiet:
            self.busy = False
        if failed:
            failed(exc)
        elif not quiet:
            self.show_error(exc)

    def _on_helper_event(self, e: dict) -> None:
        phase, pct = e.get("phase", ""), e.get("percent")
        if pct is not None:
            label = {"backup_progress": "Backing up", "restore_progress": "Restoring"}.get(phase, "Working")
            self.progress_text.set(f"{label}: {pct:.0f}%")

    def _got_limits(self, limits: ch.WaitLimits) -> None:
        self.limits = limits
        self.choices.wait_days = limits.clamp(self.choices.wait_days)

    # ------------------------------------------------------------------ widgets
    def header(self, title: str, subtitle: str = "") -> None:
        tk.Label(self.body, text=title, font=self.f_head, fg=NAVY, bg=MIST, anchor="w",
                 justify="left").pack(fill="x")
        if subtitle:
            tk.Label(self.body, text=subtitle, font=self.f_sub, fg=SLATE, bg=MIST, anchor="w",
                     justify="left", wraplength=WRAP + 40).pack(fill="x", pady=(6, 14))

    def card(self) -> ttk.Frame:
        c = ttk.Frame(self.body, style="Card.TFrame", padding=16)
        c.pack(fill="x", pady=6)
        return c

    def text(self, parent, s: str, muted: bool = False, bold: bool = False) -> ttk.Label:
        lab = ttk.Label(parent, text=s, style="Muted.Card.TLabel" if muted else "Card.TLabel",
                        wraplength=WRAP, justify="left")
        if bold:
            lab.configure(font=self.f_bold)
        lab.pack(anchor="w", pady=2, fill="x")
        return lab

    def check(self, parent, s: str, var: tk.BooleanVar, cmd: Optional[Callable] = None) -> None:
        """A checkbox whose long sentence wraps (ttk.Checkbutton text can't)."""
        row = tk.Frame(parent, bg=WHITE)
        row.pack(anchor="w", fill="x", pady=4)
        cb = ttk.Checkbutton(row, variable=var, style="Card.TCheckbutton", command=cmd)
        cb.pack(side="left", anchor="n", pady=(2, 0))
        lab = ttk.Label(row, text=s, style="Card.TLabel", wraplength=WRAP - 30, justify="left", cursor="hand2")
        lab.pack(side="left", anchor="w", fill="x")

        def toggle(_e=None):
            var.set(not var.get())
            if cmd:
                cmd()
        lab.bind("<Button-1>", toggle)

    def buttons(self) -> tk.Frame:
        row = tk.Frame(self.body, bg=MIST)
        row.pack(fill="x", pady=(14, 0))
        return row

    def show_error(self, exc: BaseException) -> None:
        code, msg = classify(exc)
        dev = self.device.word if self.device else "iPhone"
        c = self.card()
        tk.Label(c, text=msg or W.GENERIC_ERROR.format(device=dev), fg=WARN, bg=WHITE, font=self.f_bold,
                 wraplength=WRAP, justify="left").pack(anchor="w")
        try:
            paths.add_shared_paths()
            import pax_errors
            pc = pax_errors.get(code)
            self.text(c, pc.action.replace("Mac", "PC"), muted=True)
        except Exception:  # noqa: BLE001
            pass
        detail = getattr(exc, "technical", "") or ""
        self.text(c, f"{W.DETAILS}: {code}" + (f" ({detail})" if detail else ""), muted=True)

    # ------------------------------------------------------------------ 1. plug in
    def show_connect(self) -> None:
        self._set_step(0)
        self._clear()
        self.header(W.CONNECT_TITLE, W.CONNECT_HELP)
        tk.Label(self.body, text=W.NOT_FOR_PC, font=self.f_small, fg=SLATE, bg=MIST, anchor="w",
                 wraplength=WRAP + 40, justify="left").pack(fill="x", pady=(0, 8))
        self.connect_card = self.card()
        self.text(self.connect_card, W.CONNECT_SEARCHING, muted=True)
        if self.demo:
            self._driver_checked(drv.DriverStatus("ok", "apple_devices"))
        else:
            self.run_bg(drv.check, self._driver_checked, quiet=True)

    def _driver_checked(self, status: drv.DriverStatus) -> None:
        if status.ok:
            self._start_search()
            return
        for w in self.connect_card.winfo_children():
            w.destroy()
        self.text(self.connect_card, W.DRIVER_TITLE, bold=True)
        self.text(self.connect_card, W.DRIVER_HELP if status.state == "missing" else W.DRIVER_STOPPED)
        row = self.buttons()
        ttk.Button(row, text=W.DRIVER_BUTTON, style="Primary.TButton", command=drv.open_store).pack(side="left")
        ttk.Button(row, text=W.DRIVER_RECHECK, style="Secondary.TButton",
                   command=self.show_connect).pack(side="left", padx=10)

    def _start_search(self) -> None:
        if self.searching:
            return
        self.searching = True
        self.run_bg(self.session.find_devices, self._found, failed=self._search_failed, quiet=True)

    def _search_failed(self, exc: BaseException) -> None:
        self.searching = False
        if self.step == 0:
            self.root.after(int(SEARCH_EVERY_S * 1000), self._start_search)

    def _found(self, devices: list[Device]) -> None:
        self.searching = False
        if self.step != 0:
            return
        if not devices:
            self.root.after(int(SEARCH_EVERY_S * 1000), self._start_search)
            return
        self.device = devices[0]
        for w in self.connect_card.winfo_children():
            w.destroy()
        d = self.device
        if not d.paired:
            self.text(self.connect_card, W.CONNECT_NEEDS_TRUST.format(device=d.word))
            self.run_bg(lambda: self.session.connect_once(d), self._pair_answer, quiet=True)
            return
        self.text(self.connect_card, W.CONNECT_FOUND.format(name=d.name, ios=d.ios or "?"), bold=True)
        row = self.buttons()
        ttk.Button(row, text="Continue", style="Primary.TButton", command=self.show_ready).pack(side="left")

    def _pair_answer(self, state: str) -> None:
        if self.step != 0 or self.device is None:
            return
        if state == "paired":
            self.device.paired = True
            self._found([self.device])
            return
        for w in self.connect_card.winfo_children():
            w.destroy()
        self.text(self.connect_card, W.PHONE_STATE.get(state, W.PHONE_STATE["not_found"]).format(
            device=self.device.word))
        row = self.buttons()
        if state in ("trust_requested", "denied"):
            ttk.Button(row, text=W.TAPPED_TRUST if state == "trust_requested" else W.PLUGGED_BACK,
                       style="Primary.TButton", command=self._retry_pair).pack(side="left")
        else:
            self.root.after(int(SEARCH_EVERY_S * 1000), self._start_search)

    def _retry_pair(self) -> None:
        d = self.device
        if d:
            self.run_bg(lambda: self.session.connect_once(d), self._pair_answer, quiet=True)

    # ------------------------------------------------------------------ 2. get ready
    def show_ready(self) -> None:
        self._set_step(1)
        self._clear()
        d = self.device
        assert d is not None
        self.header(W.READY_TITLE.format(device=d.word), W.READY_SUBTITLE.format(device=d.word))
        c = self.card()
        self.v_findmy = tk.BooleanVar(value=self.choices.find_my_confirmed_off)
        self.check(c, W.FIND_MY_OFF, self.v_findmy, self._ready_changed)
        self.text(c, W.PASSCODE_NOTE, muted=True)
        c2 = self.card()
        if self.session.backup_path:
            self.text(c2, W.BACKUP_DONE)
        else:
            row = tk.Frame(c2, bg=WHITE)
            row.pack(anchor="w", fill="x")
            self.b_backup = ttk.Button(row, text=W.BACKUP_WITH_PAX, style="Secondary.TButton",
                                       command=self._backup)
            self.b_backup.pack(side="left")
            ttk.Label(row, text=W.BACKUP_WITH_PAX_NOTE, style="Muted.Card.TLabel").pack(side="left", padx=10)
            ttk.Label(c2, textvariable=self.progress_text, style="Muted.Card.TLabel").pack(anchor="w")
            self.v_ownbackup = tk.BooleanVar(value=self.choices.backup_confirmed)
            self.check(c2, W.BACKUP_OWN.format(device=d.word), self.v_ownbackup, self._ready_changed)
        row = self.buttons()
        self.b_ready = ttk.Button(row, text="Continue", style="Primary.TButton", command=self.show_wait)
        self.b_ready.pack(side="left")
        ttk.Button(row, text="Back", style="Secondary.TButton", command=self.show_connect).pack(side="left", padx=10)
        self._ready_changed()

    def _ready_changed(self) -> None:
        self.choices.find_my_confirmed_off = self.v_findmy.get()
        if hasattr(self, "v_ownbackup") and not self.session.backup_path:
            self.choices.backup_confirmed = self.v_ownbackup.get()
        ok = self.choices.find_my_confirmed_off and (self.session.backup_path or self.choices.backup_confirmed)
        self.b_ready.state(["!disabled"] if ok else ["disabled"])

    def _backup(self) -> None:
        d = self.device
        assert d is not None
        self.b_backup.state(["disabled"])
        self.progress_text.set("Backing up\u2026")
        self.run_bg(lambda: self.session.backup(d), lambda _p: self.show_ready(),
                    failed=lambda e: (self.show_ready(), self.show_error(e)))

    # ------------------------------------------------------------------ 3. turn-off wait
    def show_wait(self) -> None:
        self._set_step(2)
        self._clear()
        self.header(W.WAIT_TITLE, W.WAIT_HELP)
        c = self.card()
        self.v_wait = tk.StringVar(value=str(self.choices.wait_days)
                                   if self.choices.wait_days in self.limits.presets() else "custom")
        row = tk.Frame(c, bg=WHITE)
        row.pack(anchor="w")
        for days in self.limits.presets():
            label = ch.choice_title(days) + (f"  ({W.WAIT_RECOMMENDED})" if days == ch.DEFAULT_WAIT_DAYS else "")
            ttk.Radiobutton(row, text=label, value=str(days), variable=self.v_wait,
                            style="Card.TRadiobutton", command=self._wait_changed).pack(side="left", padx=(0, 18))
        crow = tk.Frame(c, bg=WHITE)
        crow.pack(anchor="w", pady=(6, 0))
        ttk.Radiobutton(crow, text=W.WAIT_CUSTOM, value="custom", variable=self.v_wait,
                        style="Card.TRadiobutton", command=self._wait_changed).pack(side="left")
        self.v_custom = tk.StringVar(value=str(self.choices.wait_days))
        lo, hi = self.limits.day_range
        e = ttk.Entry(crow, textvariable=self.v_custom, width=6)
        e.pack(side="left", padx=8)
        ttk.Label(crow, text=f"days ({lo} to {hi})", style="Muted.Card.TLabel").pack(side="left")
        self.v_custom.trace_add("write", lambda *_: self._wait_changed())
        self.text(c, W.WAIT_ALSO_APPLIES, muted=True)
        self.text(c, W.WAIT_CUSTOM_NOTE, muted=True)

        c2 = self.card()
        self.v_email = tk.StringVar(value=self.account.email if self.account else "")
        self.v_code = tk.StringVar()
        has_token = bool(self.session.escrow.token)
        if not has_token:
            self.text(c2, W.EMAIL_LABEL, bold=True)
            ttk.Entry(c2, textvariable=self.v_email, width=44).pack(anchor="w")
            self.text(c2, W.EMAIL_NOTE, muted=True)
            if self.account and self.account.code_sent_to:
                self.text(c2, W.CODE_SENT.format(email=self.account.code_sent_to))
                ttk.Label(c2, text=W.CODE_LABEL, style="Card.TLabel").pack(anchor="w")
                ttk.Entry(c2, textvariable=self.v_code, width=12).pack(anchor="w")
        self.text(c2, W.TRUSTED_LABEL, bold=True)
        self.v_partner = tk.StringVar(value=self.choices.partner_email or "")
        ttk.Entry(c2, textvariable=self.v_partner, width=44).pack(anchor="w")
        self.text(c2, W.TRUSTED_NOTE, muted=True)

        c3 = self.card()
        self.text(c3, W.TRIAL_LINE)
        self.v_support = tk.BooleanVar(value=self.choices.support_release)
        self.check(c3, W.SUPPORT_CHECKBOX, self.v_support)
        self.text(c3, W.SUPPORT_DETAIL, muted=True)

        row = self.buttons()
        self.b_wait = ttk.Button(row, text="Continue", style="Primary.TButton", command=self._save_wait)
        self.b_wait.pack(side="left")
        ttk.Button(row, text="Back", style="Secondary.TButton", command=self.show_ready).pack(side="left", padx=10)
        self.wait_error = tk.Frame(self.body, bg=MIST)
        self.wait_error.pack(fill="x")
        for v in (self.v_email, self.v_code, self.v_partner):
            v.trace_add("write", lambda *_: self._wait_changed())
        self._wait_changed()

    def _chosen_days(self) -> Optional[int]:
        sel = self.v_wait.get()
        if sel == "custom":
            return ch.parse_custom_days(self.v_custom.get(), self.limits)
        return int(sel)

    def _wait_changed(self) -> None:
        days = self._chosen_days()
        ok = days is not None and not self.busy
        if not self.session.escrow.token:
            ok = ok and ch.email_looks_valid(self.v_email.get())
            if self.account and self.account.code_sent_to:
                ok = ok and ch.code_looks_valid(self.v_code.get())
        partner = self.v_partner.get().strip() if hasattr(self, "v_partner") else ""
        if partner and not ch.email_looks_valid(partner):
            ok = False
        self.b_wait.state(["!disabled"] if ok else ["disabled"])

    def _save_wait(self) -> None:
        days = self._chosen_days()
        if days is None:
            return
        self.choices.wait_days = days
        self.choices.partner_email = self.v_partner.get().strip() or None
        self.choices.support_release = self.v_support.get()
        email = self.v_email.get().strip()
        if not self.account or self.account.email != email:
            self.account = EmailAccount(email)
        if self.account.code_sent_to:
            self.account.code = self.v_code.get().strip()
        self.b_wait.state(["disabled"])
        acct, choices = self.account, self.choices
        self.run_bg(lambda: self.session.ensure_account(acct, choices), self._account_done,
                    failed=self._account_failed)

    def _account_done(self, res) -> None:
        if res.state == "code_sent":
            self.show_wait()
            return
        if self.session.escrow.token:
            try:
                self.tokens.save(self.session.escrow.token)
            except Exception:  # noqa: BLE001
                pass
        self.show_lock_in()

    def _account_failed(self, exc: BaseException) -> None:
        for w in self.wait_error.winfo_children():
            w.destroy()
        self._wait_changed()
        self.show_error(exc)

    # ------------------------------------------------------------------ 4. lock it in
    def show_lock_in(self) -> None:
        self._set_step(3)
        self._clear()
        d = self.device
        assert d is not None
        self.header("Lock it in", W.READY_SUBTITLE.format(device=d.word))
        c = self.card()
        self.v_agree = tk.BooleanVar(value=self.choices.agreed)
        self.check(c, ch.agreement_text(d.word, self.choices.wait_days), self.v_agree, self._agree_changed)
        row = self.buttons()
        self.b_protect = ttk.Button(row, text=W.PROTECT_BUTTON.format(device=d.word), style="Primary.TButton",
                                    command=self._protect)
        self.b_protect.pack(side="left")
        ttk.Button(row, text="Back", style="Secondary.TButton", command=self.show_wait).pack(side="left", padx=10)
        self._agree_changed()

    def _agree_changed(self) -> None:
        self.choices.agreed = self.v_agree.get()
        missing = self.choices.ready_to_protect(bool(self.session.backup_path))
        self.b_protect.state(["!disabled"] if not missing and not self.busy else ["disabled"])

    def _protect(self) -> None:
        d = self.device
        assert d is not None
        self.b_protect.state(["disabled"])

        def work():
            pre = self.session.preflight(d, self.choices)
            if not pre.ok:
                raise SetupFailed("PAX-IOS-011", "\n".join(pre.blocking) or "Not ready yet.",
                                  "; ".join(pre.blocking))
            return self.session.start(d, pre, self.choices)
        self.show_working("restoring")
        self.run_bg(work, self._restored, failed=self._lock_failed)

    def _lock_failed(self, exc: BaseException) -> None:
        self.show_lock_in()
        self.show_error(exc)

    def show_working(self, phase: str) -> None:
        self._clear()
        d = self.device
        assert d is not None
        self.header(W.WORKING_TITLE.format(device=d.word), W.WORKING_HELP.format(device=d.word))
        c = self.card()
        self.text(c, W.PROGRESS[phase].format(device=d.word, name=d.name), bold=True)
        ttk.Label(c, textvariable=self.progress_text, style="Muted.Card.TLabel").pack(anchor="w")
        bar = ttk.Progressbar(c, mode="indeterminate", length=420)
        bar.pack(anchor="w", pady=8)
        bar.start(12)
        if phase in ("restoring", "waiting"):
            c2 = self.card()
            self.text(c2, W.ON_PHONE_TITLE.format(device=d.word), bold=True)
            steps = list(W.ON_PHONE_STEPS) + ([W.ON_PHONE_LIVE_STEP] if self.session.mode == "live" else [])
            for i, s in enumerate(steps, 1):
                self.text(c2, f"{i}.  {s}")
            self.phone_card = self.card()
            self.text(self.phone_card, W.PHONE_STATE.get(self.phone_state or "not_found",
                                                         W.PHONE_STATE["not_found"]).format(device=d.word),
                      muted=True)

    def _restored(self, outcome: dict) -> None:
        if self.session.supervised:
            self.show_nearly()
            return
        self.wait_started = None
        self.show_working("waiting")
        self._poll_phone()

    def _poll_phone(self) -> None:
        import time
        d = self.device
        assert d is not None
        if self.wait_started is None:
            self.wait_started = time.monotonic()
        self.run_bg(lambda: self.session.connect_once(d), self._phone_state, quiet=True)

    def _phone_state(self, state: str) -> None:
        import time
        d = self.device
        assert d is not None
        self.phone_state = state
        if state == "paired":
            self.show_working("confirming")
            self.run_bg(lambda: self.session.confirm(d, self.choices), lambda _s: self.show_nearly(),
                        failed=self._confirm_failed)
            return
        if not hasattr(self, "phone_card") or not self.phone_card.winfo_exists():
            return
        for w in self.phone_card.winfo_children():
            w.destroy()
        self.text(self.phone_card, W.PHONE_STATE[state].format(device=d.word))
        if state in ("trust_requested", "denied"):
            row = tk.Frame(self.phone_card, bg=WHITE)
            row.pack(anchor="w", pady=(6, 0))
            ttk.Button(row, text=W.TAPPED_TRUST if state == "trust_requested" else W.PLUGGED_BACK,
                       style="Primary.TButton", command=self._poll_phone).pack(side="left")
            return
        if self.wait_started and time.monotonic() - self.wait_started > WAIT_TOO_LONG_S:
            tk.Label(self.phone_card, text=W.WAITING_LONG.format(device=d.word), fg=WARN, bg=WHITE,
                     font=self.f_small, wraplength=WRAP, justify="left").pack(anchor="w")
        if SetupSession.poll_again(state):
            self.root.after(int(SEARCH_EVERY_S * 1000), self._poll_phone)

    def _confirm_failed(self, exc: BaseException) -> None:
        self.show_working("waiting")
        self.show_error(exc)
        row = self.buttons()
        ttk.Button(row, text=W.TRY_AGAIN, style="Primary.TButton",
                   command=lambda: self._phone_state("paired")).pack(side="left")

    def show_nearly(self) -> None:
        self._clear()
        d = self.device
        assert d is not None
        live = self.session.mode == "live"
        self.header(W.NEARLY_TITLE, (W.NEARLY_LIVE if live else W.NEARLY_RESTORED).format(device=d.word))
        c = self.card()
        self.text(c, W.PROGRESS["supervised"].format(device=d.word), bold=True)
        row = self.buttons()
        self.b_turn_on = ttk.Button(row, text=W.TURN_ON_BUTTON, style="Primary.TButton", command=self._turn_on)
        self.b_turn_on.pack(side="left")

    def _turn_on(self) -> None:
        d = self.device
        assert d is not None
        self.show_working("protecting")
        self.run_bg(lambda: self.session.lock_and_escrow(d, self.choices), self._locked,
                    failed=lambda e: (self.show_nearly(), self.show_error(e)))

    def _locked(self, outcome: str) -> None:
        if outcome == "pending_user":
            self.show_one_tap()
        else:
            self.show_done()

    def show_one_tap(self) -> None:
        self._clear()
        d = self.device
        assert d is not None
        self.header(W.ONE_TAP_TITLE.format(device=d.word))
        c = self.card()
        for i, s in enumerate(W.ONE_TAP_STEPS, 1):
            self.text(c, f"{i}.  {s}")
        row = self.buttons()
        ttk.Button(row, text=W.INSTALLED_BUTTON, style="Primary.TButton", command=self._check_installed).pack(
            side="left")

    def _check_installed(self) -> None:
        d = self.device
        assert d is not None

        def work():
            if not self.session.verify_installed(d):
                raise SetupFailed("PAX-PROFILE-003", "Pax can't see its profile on the phone yet.")
            return True
        self.run_bg(work, lambda _r: self.show_done(), failed=lambda e: (self.show_one_tap(), self.show_error(e)))

    # ------------------------------------------------------------------ 5. done
    def show_done(self) -> None:
        self._set_step(4)
        self._clear()
        d = self.device
        assert d is not None
        self.header(W.DONE_TITLE, W.DONE_SUBTITLE.format(device=d.word))
        c = self.card()
        self.text(c, W.FIND_MY_BACK, bold=True)
        self.text(c, W.FIND_MY_BACK_HELP, muted=True)
        c2 = self.card()
        self.text(c2, W.DONE_TURN_OFF_LATER, muted=True)
        self.text(c2, W.LIMITS_NOTE.format(device=d.word), muted=True)
        row = self.buttons()
        ttk.Button(row, text="Close", style="Primary.TButton", command=self.root.destroy).pack(side="left")


class _DemoEscrow:
    """In-memory stand-in for the server (PAX_DEMO=1): never touches the network."""

    def __init__(self):
        self.token: Optional[str] = None
        self.devices: list[dict] = []

    def wait_limits(self):
        return ch.WaitLimits.standard()

    def account_summary(self):
        return {}

    def register_account(self, email):
        return {"account_id": "demo", "token": "demo-token"}

    def start_sign_in(self, email):
        pass

    def sign_in(self, email, code, label=""):
        return {"token": "demo-token"}

    def set_wait(self, days):
        return {}

    def set_partner(self, email):
        return {}

    def block_site(self, d):
        return {}

    def set_dns_settings(self, yt):
        return {}

    def dns_info(self):
        return {"token": "DEMOtokenDEMOtokenDEMO12"}

    def register_device(self, **kw):
        self.devices.append({k: v for k, v in kw.items() if k != "removal_password"})
        return {"device_id": "demo-device"}


def main(demo: bool = False) -> int:
    root = tk.Tk()
    try:
        ico = Path(paths.resource("windows", "build", "pax.ico"))
        if ico.exists():
            root.iconbitmap(str(ico))
    except tk.TclError:
        pass
    App(root, demo=demo)
    root.mainloop()
    return 0
