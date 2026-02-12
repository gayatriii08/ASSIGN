"""
╔══════════════════════════════════════════════════════════════╗
║            NETSCOUT — Advanced Port Scanner Tool             ║
║          Educational Network Discovery & Analysis            ║
╚══════════════════════════════════════════════════════════════╝

FEATURES:
─────────
• Fast multi-threaded port scanning
• Common port presets (Top 100, Web, Database, etc.)
• Custom port ranges and lists
• Service detection
• Banner grabbing
• Scan history with export
• Real-time progress tracking
• OS fingerprinting hints

⚠️  WARNING: Only scan networks you own or have permission to test.
    Unauthorized port scanning may be illegal in your jurisdiction.
"""

import socket
import threading
import queue
import time
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
from datetime import datetime
import json


# ═════════════════════════════════════════════════════════════
#  SECTION 1: PORT SCANNING ENGINE
# ═════════════════════════════════════════════════════════════

# Common service database
COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    27017: "MongoDB",
}

# Port presets
PORT_PRESETS = {
    "Top 20": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443],
    "Web Servers": [80, 443, 8000, 8008, 8080, 8443, 8888, 9000, 9090],
    "Mail Servers": [25, 110, 143, 465, 587, 993, 995],
    "Databases": [1433, 1521, 3306, 5432, 6379, 27017, 27018, 27019],
    "File Transfer": [20, 21, 22, 69, 115, 445],
    "Remote Access": [22, 23, 3389, 5900, 5901],
    "All (1-1024)": list(range(1, 1025)),
}


class PortScanner:
    """
    Multi-threaded port scanner with banner grabbing.
    """
    
    def __init__(self, target, ports, timeout=1.0, max_threads=100):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.max_threads = max_threads
        self.results = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        
    def resolve_target(self):
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            return None
    
    def scan_port(self, port):
        """Scan a single port and grab banner if possible."""
        if self.stop_event.is_set():
            return
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                # Port is open - try banner grab
                banner = None
                service = COMMON_PORTS.get(port, "Unknown")
                
                try:
                    # Send probe based on port
                    if port in [80, 8080, 8000, 8443]:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    elif port == 22:
                        pass  # SSH sends banner automatically
                    elif port == 21:
                        pass  # FTP sends banner automatically
                    elif port == 25:
                        pass  # SMTP sends banner
                    else:
                        sock.send(b"\r\n")
                    
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if len(banner) > 200:
                        banner = banner[:200] + "..."
                except:
                    banner = None
                
                with self.lock:
                    self.results.append({
                        'port': port,
                        'state': 'OPEN',
                        'service': service,
                        'banner': banner
                    })
            
            sock.close()
            
        except socket.timeout:
            pass
        except Exception:
            pass
    
    def scan(self, progress_callback=None):
        """Execute the scan with threading."""
        ip = self.resolve_target()
        if not ip:
            return {'error': f'Cannot resolve hostname: {self.target}'}
        
        start_time = time.time()
        total_ports = len(self.ports)
        scanned = 0
        
        # Use thread pool
        port_queue = queue.Queue()
        for port in self.ports:
            port_queue.put(port)
        
        def worker():
            nonlocal scanned
            while not port_queue.empty() and not self.stop_event.is_set():
                try:
                    port = port_queue.get(timeout=0.1)
                    self.scan_port(port)
                    
                    with self.lock:
                        scanned += 1
                        if progress_callback:
                            progress_callback(scanned, total_ports)
                    
                    port_queue.task_done()
                except queue.Empty:
                    break
        
        # Start threads
        threads = []
        for _ in range(min(self.max_threads, total_ports)):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for completion
        for t in threads:
            t.join()
        
        end_time = time.time()
        
        # Sort results by port number
        self.results.sort(key=lambda x: x['port'])
        
        return {
            'target': self.target,
            'ip': ip,
            'scanned_ports': total_ports,
            'open_ports': len(self.results),
            'duration': round(end_time - start_time, 2),
            'results': self.results,
        }
    
    def stop(self):
        """Stop the scan."""
        self.stop_event.set()


# ═════════════════════════════════════════════════════════════
#  SECTION 2: GUI APPLICATION
# ═════════════════════════════════════════════════════════════

# Color scheme - Modern dark theme
BG_DARK = "#1a1d23"
BG_PANEL = "#22252b"
BG_INPUT = "#2a2d35"
BG_BORDER = "#3a3d45"
FG_PRIMARY = "#e8eaed"
FG_SECONDARY = "#9aa0a6"
FG_ACCENT = "#4fc3f7"
FG_SUCCESS = "#66bb6a"
FG_WARNING = "#ffa726"
FG_ERROR = "#ef5350"


class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.scanner = None
        self.scan_thread = None
        self.scan_history = []
        
        self._build_window()
        self._build_header()
        self._build_target_frame()
        self._build_port_config()
        self._build_scan_controls()
        self._build_results_area()
        self._build_status_bar()
        
    def _build_window(self):
        self.root.title("NetScout — Port Scanner")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)
        self.root.configure(bg=BG_DARK)
        
        # Configure grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(4, weight=1)  # Results area expands
    
    def _build_header(self):
        header = tk.Frame(self.root, bg=BG_PANEL, height=80)
        header.grid(row=0, column=0, sticky="ew")
        
        # Top accent line
        tk.Frame(header, bg=FG_ACCENT, height=3).pack(fill="x")
        
        # Title section
        title_frame = tk.Frame(header, bg=BG_PANEL)
        title_frame.pack(fill="x", padx=25, pady=15)
        
        tk.Label(
            title_frame,
            text="⚡ NetScout",
            font=("Segoe UI", 20, "bold"),
            fg=FG_ACCENT,
            bg=BG_PANEL
        ).pack(side="left")
        
        tk.Label(
            title_frame,
            text="Advanced Port Scanner & Service Discovery",
            font=("Segoe UI", 10),
            fg=FG_SECONDARY,
            bg=BG_PANEL
        ).pack(side="left", padx=15, pady=2)
        
        # Warning
        warn_frame = tk.Frame(header, bg="#3d2a00")
        warn_frame.pack(fill="x", padx=25, pady=5)
        
        tk.Label(
            warn_frame,
            text="⚠ Only scan networks you own or have explicit permission to test",
            font=("Segoe UI", 8),
            fg=FG_WARNING,
            bg="#3d2a00"
        ).pack(padx=10, pady=5)
    
    def _build_target_frame(self):
        frame = tk.Frame(self.root, bg=BG_DARK)
        frame.grid(row=1, column=0, sticky="ew", padx=25, pady=10)
        frame.columnconfigure(1, weight=1)
        
        tk.Label(
            frame,
            text="TARGET",
            font=("Segoe UI", 9, "bold"),
            fg=FG_SECONDARY,
            bg=BG_DARK
        ).grid(row=0, column=0, sticky="w", pady=5)
        
        # Target input
        self.target_var = tk.StringVar(value="127.0.0.1")
        
        target_entry = tk.Entry(
            frame,
            textvariable=self.target_var,
            font=("Consolas", 11),
            bg=BG_INPUT,
            fg=FG_PRIMARY,
            insertbackground=FG_ACCENT,
            relief="flat",
            bd=0
        )
        target_entry.grid(row=1, column=0, columnspan=2, sticky="ew", ipady=10, padx=2)
        
        tk.Label(
            frame,
            text="IP address or hostname (e.g., 192.168.1.1 or example.com)",
            font=("Segoe UI", 8),
            fg=FG_SECONDARY,
            bg=BG_DARK
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=3)
    
    def _build_port_config(self):
        frame = tk.Frame(self.root, bg=BG_DARK)
        frame.grid(row=2, column=0, sticky="ew", padx=25, pady=10)
        frame.columnconfigure(1, weight=1)
        
        tk.Label(
            frame,
            text="PORT CONFIGURATION",
            font=("Segoe UI", 9, "bold"),
            fg=FG_SECONDARY,
            bg=BG_DARK
        ).grid(row=0, column=0, sticky="w", pady=5)
        
        # Preset selection
        preset_frame = tk.Frame(frame, bg=BG_DARK)
        preset_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        
        tk.Label(
            preset_frame,
            text="Preset:",
            font=("Segoe UI", 9),
            fg=FG_PRIMARY,
            bg=BG_DARK
        ).pack(side="left", padx=5)
        
        self.preset_var = tk.StringVar(value="Top 20")
        preset_combo = ttk.Combobox(
            preset_frame,
            textvariable=self.preset_var,
            values=list(PORT_PRESETS.keys()),
            state="readonly",
            width=20,
            font=("Segoe UI", 9)
        )
        preset_combo.pack(side="left", padx=5)
        preset_combo.bind("<<ComboboxSelected>>", self._on_preset_change)
        
        # Custom ports
        custom_frame = tk.Frame(frame, bg=BG_DARK)
        custom_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=5)
        
        tk.Label(
            custom_frame,
            text="Custom:",
            font=("Segoe UI", 9),
            fg=FG_PRIMARY,
            bg=BG_DARK
        ).pack(side="left", padx=5)
        
        self.custom_ports_var = tk.StringVar()
        custom_entry = tk.Entry(
            custom_frame,
            textvariable=self.custom_ports_var,
            font=("Consolas", 10),
            bg=BG_INPUT,
            fg=FG_PRIMARY,
            insertbackground=FG_ACCENT,
            relief="flat",
            bd=0,
            width=50
        )
        custom_entry.pack(side="left", padx=5, ipady=6)
        
        tk.Label(
            custom_frame,
            text="(e.g., 80,443,8080 or 1-1000)",
            font=("Segoe UI", 8),
            fg=FG_SECONDARY,
            bg=BG_DARK
        ).pack(side="left", padx=5)
    
    def _build_scan_controls(self):
        frame = tk.Frame(self.root, bg=BG_DARK)
        frame.grid(row=3, column=0, sticky="ew", padx=25, pady=10)
        
        # Scan button
        self.scan_btn = tk.Button(
            frame,
            text="🔍  START SCAN",
            font=("Segoe UI", 11, "bold"),
            bg=FG_ACCENT,
            fg="#000000",
            activebackground="#6fd5ff",
            relief="flat",
            bd=0,
            cursor="hand2",
            command=self._start_scan
        )
        self.scan_btn.pack(side="left", padx=5, ipadx=20, ipady=10)
        
        # Stop button
        self.stop_btn = tk.Button(
            frame,
            text="⏹  STOP",
            font=("Segoe UI", 10, "bold"),
            bg=BG_INPUT,
            fg=FG_ERROR,
            activebackground=BG_BORDER,
            relief="flat",
            bd=0,
            cursor="hand2",
            command=self._stop_scan,
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=5, ipadx=15, ipady=10)
        
        # Clear button
        tk.Button(
            frame,
            text="🗑  CLEAR",
            font=("Segoe UI", 10),
            bg=BG_INPUT,
            fg=FG_SECONDARY,
            activebackground=BG_BORDER,
            relief="flat",
            bd=0,
            cursor="hand2",
            command=self._clear_results
        ).pack(side="left", padx=5, ipadx=15, ipady=10)
        
        # Export button
        tk.Button(
            frame,
            text="💾  EXPORT",
            font=("Segoe UI", 10),
            bg=BG_INPUT,
            fg=FG_SECONDARY,
            activebackground=BG_BORDER,
            relief="flat",
            bd=0,
            cursor="hand2",
            command=self._export_results
        ).pack(side="left", padx=5, ipadx=15, ipady=10)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            frame,
            variable=self.progress_var,
            mode='determinate',
            length=300
        )
        self.progress_bar.pack(side="right", padx=10)
    
    def _build_results_area(self):
        frame = tk.Frame(self.root, bg=BG_DARK)
        frame.grid(row=4, column=0, sticky="nsew", padx=25, pady=10)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        
        tk.Label(
            frame,
            text="SCAN RESULTS",
            font=("Segoe UI", 9, "bold"),
            fg=FG_SECONDARY,
            bg=BG_DARK
        ).grid(row=0, column=0, sticky="w", pady=5)
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(
            frame,
            font=("Consolas", 10),
            bg=BG_PANEL,
            fg=FG_PRIMARY,
            insertbackground=FG_ACCENT,
            relief="flat",
            bd=0,
            wrap="word",
            state="disabled"
        )
        self.results_text.grid(row=1, column=0, sticky="nsew", padx=2, pady=2)
        
        # Configure tags for colored output
        self.results_text.tag_configure("header", foreground=FG_ACCENT, font=("Consolas", 10, "bold"))
        self.results_text.tag_configure("success", foreground=FG_SUCCESS, font=("Consolas", 10, "bold"))
        self.results_text.tag_configure("warning", foreground=FG_WARNING)
        self.results_text.tag_configure("error", foreground=FG_ERROR, font=("Consolas", 10, "bold"))
        self.results_text.tag_configure("info", foreground=FG_SECONDARY)
        self.results_text.tag_configure("port", foreground=FG_ACCENT, font=("Consolas", 10, "bold"))
        self.results_text.tag_configure("service", foreground=FG_SUCCESS)
        self.results_text.tag_configure("banner", foreground=FG_SECONDARY, font=("Consolas", 9))
    
    def _build_status_bar(self):
        self.status_frame = tk.Frame(self.root, bg=BG_PANEL, height=30)
        self.status_frame.grid(row=5, column=0, sticky="ew")
        
        self.status_label = tk.Label(
            self.status_frame,
            text="Ready to scan",
            font=("Segoe UI", 9),
            fg=FG_SECONDARY,
            bg=BG_PANEL,
            anchor="w"
        )
        self.status_label.pack(side="left", padx=25, pady=5)
    
    def _write(self, text, tag="info"):
        """Write text to results area."""
        self.results_text.config(state="normal")
        self.results_text.insert("end", text, tag)
        self.results_text.config(state="disabled")
        self.results_text.see("end")
    
    def _writeln(self, text="", tag="info"):
        """Write line to results area."""
        self._write(text + "\n", tag)
    
    def _clear_results(self):
        """Clear the results area."""
        self.results_text.config(state="normal")
        self.results_text.delete("1.0", "end")
        self.results_text.config(state="disabled")
        self.status_label.config(text="Ready to scan")
        self.progress_var.set(0)
    
    def _on_preset_change(self, event=None):
        """Clear custom ports when preset is selected."""
        self.custom_ports_var.set("")
    
    def _parse_ports(self):
        """Parse port configuration."""
        custom = self.custom_ports_var.get().strip()
        
        if custom:
            # Parse custom ports
            ports = []
            for part in custom.split(','):
                part = part.strip()
                if '-' in part:
                    # Range
                    try:
                        start, end = map(int, part.split('-'))
                        ports.extend(range(start, end + 1))
                    except:
                        pass
                else:
                    # Single port
                    try:
                        ports.append(int(part))
                    except:
                        pass
            return list(set(ports))
        else:
            # Use preset
            preset = self.preset_var.get()
            return PORT_PRESETS.get(preset, PORT_PRESETS["Top 20"])
    
    def _start_scan(self):
        """Start the port scan."""
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or hostname")
            return
        
        ports = self._parse_ports()
        if not ports:
            messagebox.showerror("Error", "No valid ports to scan")
            return
        
        # Disable controls
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        
        # Clear results
        self._clear_results()
        
        # Display scan info
        self._writeln("=" * 80, "header")
        self._writeln(f"  NetScout Port Scan Report", "header")
        self._writeln(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "info")
        self._writeln("=" * 80, "header")
        self._writeln()
        self._writeln(f"Target:        {target}", "info")
        self._writeln(f"Ports:         {len(ports)} ports", "info")
        self._writeln(f"Threads:       100", "info")
        self._writeln()
        self._writeln("-" * 80, "info")
        self._writeln()
        
        # Create scanner
        self.scanner = PortScanner(target, ports, timeout=1.0, max_threads=100)
        
        # Start scan in thread
        self.scan_thread = threading.Thread(target=self._run_scan, daemon=True)
        self.scan_thread.start()
    
    def _run_scan(self):
        """Execute the scan (runs in thread)."""
        def progress_callback(scanned, total):
            progress = (scanned / total) * 100
            self.root.after(0, lambda: self.progress_var.set(progress))
            self.root.after(0, lambda: self.status_label.config(
                text=f"Scanning... {scanned}/{total} ports ({progress:.1f}%)"
            ))
        
        # Run scan
        result = self.scanner.scan(progress_callback)
        
        # Display results on main thread
        self.root.after(0, lambda: self._display_results(result))
    
    def _display_results(self, result):
        """Display scan results."""
        if 'error' in result:
            self._writeln(f"❌ ERROR: {result['error']}", "error")
            self._finalize_scan()
            return
        
        # Summary
        self._writeln(f"IP Address:    {result['ip']}", "info")
        self._writeln(f"Scan Duration: {result['duration']} seconds", "info")
        self._writeln()
        self._writeln(f"Ports Scanned: {result['scanned_ports']}", "info")
        self._writeln(f"Open Ports:    {result['open_ports']}", "success")
        self._writeln()
        self._writeln("-" * 80, "info")
        self._writeln()
        
        if result['open_ports'] > 0:
            self._writeln("OPEN PORTS:", "header")
            self._writeln()
            
            for r in result['results']:
                self._write(f"  PORT {r['port']:>5}  ", "port")
                self._write(f"{r['state']:>6}  ", "success")
                self._write(f"{r['service']}", "service")
                self._writeln()
                
                if r['banner']:
                    # Format banner
                    banner_lines = r['banner'].split('\n')
                    for line in banner_lines[:3]:  # Max 3 lines
                        if line.strip():
                            self._writeln(f"           └─ {line.strip()}", "banner")
                    self._writeln()
        else:
            self._writeln("No open ports found.", "warning")
        
        self._writeln()
        self._writeln("=" * 80, "header")
        self._writeln(f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "info")
        self._writeln("=" * 80, "header")
        self._writeln()
        
        # Save to history
        self.scan_history.append({
            'timestamp': datetime.now().isoformat(),
            'target': result['target'],
            'results': result
        })
        
        self._finalize_scan()
    
    def _stop_scan(self):
        """Stop the current scan."""
        if self.scanner:
            self.scanner.stop()
            self._writeln()
            self._writeln("⏹ Scan stopped by user", "warning")
            self._writeln()
            self._finalize_scan()
    
    def _finalize_scan(self):
        """Re-enable controls after scan."""
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="Scan completed")
        self.progress_var.set(0)
    
    def _export_results(self):
        """Export scan history to JSON."""
        if not self.scan_history:
            messagebox.showinfo("Info", "No scan results to export")
            return
        
        filename = f"portscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.scan_history, f, indent=2)
            
            messagebox.showinfo("Success", f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {e}")


# ═════════════════════════════════════════════════════════════
#  SECTION 3: MAIN ENTRY POINT
# ═════════════════════════════════════════════════════════════

def main():
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()