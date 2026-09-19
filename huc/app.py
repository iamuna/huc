from __future__ import annotations

import os
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

import psutil

from .blocklist import BlockList, CRITICAL_NAMES
from .monitor import ProcessSampler, ProcessUsage


class HucApp(tk.Tk):
    REFRESH_MS = 1000

    def __init__(self) -> None:
        super().__init__()
        self.title("HUC — Hardware Usage Controller")
        self.geometry("1320x760")
        self.minsize(980, 560)

        self.blocklist = BlockList()
        self.sampler = ProcessSampler(self.blocklist)
        self.rows: dict[str, ProcessUsage] = {}
        self.sort_column = "cpu"
        self.sort_reverse = True
        self.filter_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Starting…")
        self._refresh_job: str | None = None

        self._build_ui()
        self.after(150, self.refresh)

    def _build_ui(self) -> None:
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text="HUC", font=("Segoe UI", 18, "bold")).pack(side="left")
        ttk.Label(top, text="  Hardware Usage Controller", font=("Segoe UI", 11)).pack(side="left")
        ttk.Label(top, text="Filter:").pack(side="left", padx=(25, 5))
        entry = ttk.Entry(top, textvariable=self.filter_var, width=32)
        entry.pack(side="left")
        entry.bind("<Return>", lambda _e: self.refresh())
        ttk.Button(top, text="Refresh", command=self.refresh).pack(side="right")

        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True, padx=10)

        columns = ("pid", "name", "cpu", "ram", "gpu", "gpumem", "read", "write", "threads", "blocked", "path")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        labels = {
            "pid": "PID", "name": "Process", "cpu": "CPU %", "ram": "RAM MB",
            "gpu": "GPU %", "gpumem": "GPU Mem %", "read": "Disk R MB/s",
            "write": "Disk W MB/s", "threads": "Threads", "blocked": "Blocked",
            "path": "Executable path",
        }
        widths = {
            "pid": 70, "name": 170, "cpu": 80, "ram": 95, "gpu": 80, "gpumem": 95,
            "read": 105, "write": 105, "threads": 70, "blocked": 70, "path": 420,
        }
        for col in columns:
            self.tree.heading(col, text=labels[col], command=lambda c=col: self.sort_by(c))
            self.tree.column(
                col,
                width=widths[col],
                minwidth=55,
                anchor="w" if col in {"name", "path"} else "e",
            )

        yscroll = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        actions = ttk.Frame(self, padding=10)
        actions.pack(fill="x")
        ttk.Button(actions, text="Open file location", command=self.locate_selected).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="End process", command=self.kill_selected).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="BAN executable", command=self.ban_selected).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Unban executable", command=self.unban_selected).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Show blocked", command=self.show_blocked).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Uninstall HUC…", command=self.uninstall_huc).pack(side="left")
        ttk.Label(actions, textvariable=self.status_var).pack(side="right")

        note = (
            "BAN stores executable path + SHA-256. HUC Guard terminates matching launches. "
            "Protected Windows processes cannot be banned."
        )
        ttk.Label(self, text=note, padding=(10, 0, 10, 10)).pack(fill="x")

    def sort_by(self, col: str) -> None:
        if self.sort_column == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = col
            self.sort_reverse = col not in {"name", "path", "blocked"}
        self.refresh()

    def _sort_value(self, row: ProcessUsage):
        return {
            "pid": row.pid,
            "name": row.name.lower(),
            "cpu": row.cpu_percent,
            "ram": row.ram_mb,
            "gpu": -1 if row.gpu_percent is None else row.gpu_percent,
            "gpumem": -1 if row.gpu_mem_percent is None else row.gpu_mem_percent,
            "read": row.disk_read_mbps,
            "write": row.disk_write_mbps,
            "threads": row.threads,
            "blocked": row.blocked,
            "path": row.path.lower(),
        }[self.sort_column]

    def refresh(self) -> None:
        if self._refresh_job is not None:
            try:
                self.after_cancel(self._refresh_job)
            except tk.TclError:
                pass
            self._refresh_job = None

        try:
            self.blocklist.reload()
            data = self.sampler.sample()
        except Exception as exc:
            self.status_var.set(f"Monitor error: {exc}")
            self._refresh_job = self.after(self.REFRESH_MS, self.refresh)
            return

        query = self.filter_var.get().strip().lower()
        if query:
            data = [
                row
                for row in data
                if query in row.name.lower()
                or query in row.path.lower()
                or query == str(row.pid)
            ]
        data.sort(key=self._sort_value, reverse=self.sort_reverse)

        selected_pid = None
        sel = self.tree.selection()
        if sel and sel[0] in self.rows:
            selected_pid = self.rows[sel[0]].pid

        for item in self.tree.get_children():
            self.tree.delete(item)
        self.rows.clear()

        for row in data:
            iid = f"p{row.pid}"
            self.rows[iid] = row
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    row.pid,
                    row.name,
                    f"{row.cpu_percent:.1f}",
                    f"{row.ram_mb:.1f}",
                    "—" if row.gpu_percent is None else f"{row.gpu_percent:.0f}",
                    "—" if row.gpu_mem_percent is None else f"{row.gpu_mem_percent:.0f}",
                    f"{row.disk_read_mbps:.2f}",
                    f"{row.disk_write_mbps:.2f}",
                    row.threads,
                    "YES" if row.blocked else "",
                    row.path or "<access denied / system>",
                ),
            )
            if row.pid == selected_pid:
                self.tree.selection_set(iid)
                self.tree.see(iid)

        self.status_var.set(
            f"{len(data)} processes | GPU source: {self.sampler.gpu_source} | "
            f"{len(self.blocklist.rules())} blocked"
        )
        self._refresh_job = self.after(self.REFRESH_MS, self.refresh)

    def selected(self) -> ProcessUsage | None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("HUC", "Select a process first.")
            return None
        return self.rows.get(sel[0])

    def locate_selected(self) -> None:
        row = self.selected()
        if not row:
            return
        if not row.path or not os.path.isfile(row.path):
            messagebox.showerror("HUC", "The executable path is unavailable.")
            return
        if os.name != "nt":
            messagebox.showerror("HUC", "Open file location is currently Windows-only.")
            return
        subprocess.Popen(["explorer.exe", f"/select,{row.path}"])

    def kill_selected(self) -> None:
        row = self.selected()
        if not row:
            return
        if row.name.lower() in CRITICAL_NAMES or row.pid in {0, 4, os.getpid()}:
            messagebox.showerror("HUC", f"{row.name} is protected and cannot be ended by HUC.")
            return
        if not messagebox.askyesno("End process", f"End {row.name} (PID {row.pid})?"):
            return
        try:
            psutil.Process(row.pid).kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            messagebox.showerror("HUC", str(exc))
        self.refresh()

    def ban_selected(self) -> None:
        row = self.selected()
        if not row:
            return
        if not row.path or not os.path.isfile(row.path):
            messagebox.showerror("HUC", "HUC needs a readable executable path to create a ban.")
            return
        if row.name.lower() in CRITICAL_NAMES:
            messagebox.showerror("HUC", f"{row.name} is protected and cannot be banned.")
            return
        if not messagebox.askyesno(
            "BAN executable",
            f"Ban this executable?\n\n{row.path}\n\n"
            "HUC will store its exact path and SHA-256. With HUC Guard installed, "
            "matching launches are terminated automatically.",
        ):
            return
        try:
            rule = self.blocklist.add_path(row.path)
            try:
                psutil.Process(row.pid).kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        except (OSError, ValueError) as exc:
            messagebox.showerror("HUC", str(exc))
            return
        self.status_var.set(f"Banned {rule.name}")
        self.refresh()

    def unban_selected(self) -> None:
        row = self.selected()
        if not row:
            return
        if not row.path:
            messagebox.showerror("HUC", "This process has no readable executable path.")
            return
        removed = self.blocklist.remove(path=row.path)
        if not removed:
            messagebox.showinfo("HUC", "That executable is not in the blocklist.")
        else:
            self.status_var.set(f"Unbanned {row.name}")
        self.refresh()

    def show_blocked(self) -> None:
        rules = self.blocklist.rules()
        if not rules:
            messagebox.showinfo("Blocked executables", "The blocklist is empty.")
            return
        text = "\n\n".join(
            f"{r.name}\n{r.path}\nSHA-256: {r.sha256}"
            for r in rules
        )
        win = tk.Toplevel(self)
        win.title("HUC — Blocked executables")
        win.geometry("850x430")
        box = tk.Text(win, wrap="word")
        box.insert("1.0", text)
        box.configure(state="disabled")
        box.pack(fill="both", expand=True, padx=10, pady=10)

    def uninstall_huc(self) -> None:
        if os.name != "nt":
            messagebox.showerror("HUC", "The built-in uninstaller is currently Windows-only.")
            return

        answer = messagebox.askyesnocancel(
            "Uninstall HUC",
            "Choose an uninstall mode:\n\n"
            "Yes = FULL uninstall (Guard, HUC data, .venv, and this program folder)\n"
            "No = remove Guard + HUC data only; keep program files\n"
            "Cancel = do nothing",
        )
        if answer is None:
            return

        root = Path(__file__).resolve().parents[1]
        script = root / "uninstall_huc.ps1"
        if not script.exists():
            messagebox.showerror("HUC", f"Uninstaller not found:\n{script}")
            return

        args = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-WaitForPid",
            str(os.getpid()),
        ]
        if answer:
            args.append("-RemoveProgramFiles")

        try:
            subprocess.Popen(args, cwd=str(root))
        except OSError as exc:
            messagebox.showerror("HUC", f"Could not launch uninstaller: {exc}")
            return

        self.destroy()


def main() -> int:
    app = HucApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
