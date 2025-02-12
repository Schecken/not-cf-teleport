#!/usr/bin/env python3
import collections
import collections.abc
if not hasattr(collections, 'Callable'):
    collections.Callable = collections.abc.Callable

import argparse
import concurrent.futures
import requests
import json
import re
import time
import uuid
import os
import tempfile
import shutil
import subprocess
from rich.console import Console
from rich.text import Text
from bs4 import BeautifulSoup

# For TOR control if needed elsewhere.
from stem import Signal
from stem.control import Controller

console = Console()

#################################
# Helper: pad_center – used for formatting output.
#################################
def pad_center(markup: str, width: int) -> Text:
    text = Text.from_markup(markup)
    current_width = text.cell_len
    if current_width < width:
        total_padding = width - current_width
        left_padding = total_padding // 2
        right_padding = total_padding - left_padding
        text = Text(" " * left_padding) + text + Text(" " * right_padding)
    return text

#################################
# Minimal JavaScript evaluator for proxynova expressions.
#################################
def safe_eval(expr: str) -> int:
    try:
        return int(eval(expr, {"__builtins__": None}, {}))
    except Exception:
        return 0

def apply_method(value, method, args):
    if method == "substring":
        parts = args.split(',')
        if len(parts) == 2:
            start = safe_eval(parts[0].strip())
            end   = safe_eval(parts[1].strip())
            if isinstance(value, str):
                return value[start:end]
            else:
                return "".join(value)[start:end]
        return value
    elif method == "repeat":
        n = safe_eval(args.strip())
        return value * n if isinstance(value, str) else value
    elif method == "split":
        delim = args.strip()
        if delim.startswith('"') and delim.endswith('"'):
            delim = delim[1:-1]
        if delim == "":
            return list(value)
        return list(value.split(delim))
    elif method == "reverse":
        return list(reversed(value)) if isinstance(value, list) else list(reversed(value))
    elif method == "join":
        delim = args.strip()
        if delim.startswith('"') and delim.endswith('"'):
            delim = delim[1:-1]
        return delim.join(value) if isinstance(value, list) else str(value)
    else:
        return value

def parse_term(expr: str) -> (str, str):
    m = re.match(r'^"([^"]+)"((?:\.[a-zA-Z]+\([^)]*\))*)', expr)
    if not m:
        return "", expr
    literal = m.group(1)
    chain = m.group(2)
    result = literal
    for method_match in re.finditer(r'\.([a-zA-Z]+)\(([^)]*)\)', chain):
        method = method_match.group(1)
        args = method_match.group(2)
        result = apply_method(result, method, args)
    remaining = expr[m.end():]
    return result, remaining

def eval_js_expr(expr: str) -> str:
    term_val, remaining = parse_term(expr)
    result = term_val
    while remaining.startswith(".concat("):
        remaining = remaining[len(".concat("):]
        next_term, remaining = parse_term(remaining)
        result += next_term
        if remaining.startswith(")"):
            remaining = remaining[1:]
        else:
            break
    return result

def eval_js_document_write(script_text: str) -> str:
    script_text = script_text.strip()
    prefix = "document.write("
    if script_text.startswith(prefix) and script_text.endswith(")"):
        inner = script_text[len(prefix):-1]
        return eval_js_expr(inner)
    return ""

#################################
# End of JS evaluator
#################################

def normalize_proxy(proxy: str) -> str:
    for scheme in ["http://", "https://", "socks5://"]:
        if proxy.startswith(scheme):
            return proxy[len(scheme):]
    return proxy.strip()

def fetch_proxies_sslproxies(html_text):
    proxies = []
    soup = BeautifulSoup(html_text, 'html.parser')
    container = soup.find('div', class_='fpl-list')
    if container:
        table = container.find('table')
        if table:
            tbody = table.find('tbody')
            if tbody:
                for row in tbody.find_all('tr'):
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        ip = "".join(cols[0].stripped_strings)
                        port = "".join(cols[1].stripped_strings)
                        if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', ip) and re.match(r'^\d{2,5}$', port):
                            proxies.append(f"{ip}:{port}")
    return proxies

def fetch_proxies_proxynova(html_text):
    proxies = []
    soup = BeautifulSoup(html_text, 'html.parser')
    table = soup.find('table', id='tbl_proxy_list')
    if table:
        tbody = table.find('tbody')
        if tbody:
            for row in tbody.find_all('tr'):
                cols = row.find_all('td')
                if len(cols) >= 2:
                    ip = ""
                    script_tag = cols[0].find('script')
                    if script_tag and script_tag.string:
                        ip = eval_js_document_write(script_tag.string)
                    else:
                        ip = cols[0].get_text(strip=True)
                    port = cols[1].get_text(strip=True)
                    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', ip) and re.match(r'^\d{2,5}$', port):
                        proxies.append(f"{ip}:{port}")
    return proxies

def fetch_proxies_from_source(url, parse_type='text'):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        html = response.text
        if parse_type == 'text':
            lines = html.splitlines()
            return [line.strip() for line in lines if line.strip()]
        elif parse_type == 'html-ssl':
            return fetch_proxies_sslproxies(html)
        elif parse_type == 'proxynova':
            return fetch_proxies_proxynova(html)
        else:
            return []
    except Exception as e:
        console.log(f"[red1]Error fetching proxies from {url}: {e}[/red1]")
        return []

def gather_proxies(sources, verbose=False):
    proxies_set = set()
    for name, source in sources.items():
        console.log(f"[blue]Fetching proxies from {name}...[/blue]")
        source_proxies = fetch_proxies_from_source(source['url'], source.get('parse_type', 'text'))
        for p in source_proxies:
            if verbose:
                console.log(f"[yellow]Debug: Found proxy: {p}[/yellow]")
            normalized = normalize_proxy(p)
            if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}$', normalized):
                proxies_set.add(normalized)
    return list(proxies_set)

#################################
# HTTP Request Using a Proxy – Checks Cache Status.
#################################
def check_cache(proxy, url, country, dc, verbose=False):
    proxy_url = f"http://{proxy}"
    proxies = {"http": proxy_url, "https": proxy_url}
    headers = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/90.0.4430.93 Safari/537.36"),
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive"
    }
    if verbose:
        console.log(f"[blue]HTTP Request: GET {url} using proxy {proxy_url} with headers: {headers}[/blue]")
    try:
        r = requests.get(url, proxies=proxies, headers=headers, timeout=10)
        r.raise_for_status()
        if verbose:
            console.log(f"[green]Response Status: {r.status_code}[/green]")
            console.log(f"[green]Response Headers: {r.headers}[/green]")
        cf_status = r.headers.get("CF-Cache-Status", "") or r.headers.get("X-Cache", "")
        cf_status = cf_status.upper()
        if "HIT" in cf_status:
            age_val = r.headers.get("Age", "")
            try:
                age_seconds = int(age_val)
                minutes = age_seconds // 60
                seconds = age_seconds % 60
                age_str = f"age: {minutes}:{seconds:02d}"
            except Exception:
                age_str = ""
            return (country, dc, "HIT", age_str, url, proxy)
        else:
            return (country, dc, "MISS", "", url, proxy)
    except Exception as e:
        if verbose:
            console.log(f"[red1]Error checking cache with proxy {proxy}: {e}[/red1]")
        return (country, dc, "MISS", "", url, proxy)

#################################
# HTTP Proxies Check Mode (uses input file)
#################################
def check_cache_for_all_http(input_file, url, verbose=False):
    try:
        with open(input_file, "r") as f:
            validated = json.load(f)
    except Exception as e:
        console.log(f"[red1]Error loading validated proxies from {input_file}: {e}[/red1]")
        return

    try:
        with open("DC-Colos.json", "r") as f:
            dc_colos = json.load(f)
    except Exception as e:
        console.log(f"[red1]Error loading DC-Colos.json: {e}[/red1]")
        dc_colos = {}
    try:
        with open("country.json", "r") as f:
            country_map = json.load(f)
    except Exception as e:
        console.log(f"[red1]Error loading country.json: {e}[/red1]")
        country_map = {}

    tasks = []
    for country, dc_dict in validated.items():
        for dc, proxy_list in dc_dict.items():
            if proxy_list:
                tasks.append((country, dc, proxy_list[0]))

    total_tasks = len(tasks)
    results = []
    count = 0
    index_width = 12
    status_width = 12
    proxy_width = 28
    country_width = 10
    dc_width = 10
    age_width = 14

    console.log("[bold blue]Checking cache via HTTP proxies...[/bold blue]")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_task = {
            executor.submit(check_cache, proxy, url, country, dc, verbose): (country, dc, proxy)
            for country, dc, proxy in tasks
        }
        for future in concurrent.futures.as_completed(future_to_task):
            count += 1
            country, dc, proxy = future_to_task[future]
            result = future.result()  # (country, dc, status, age_str, url, proxy)
            results.append(result)
            status_markup = "[green3]Success[/green3]" if result[2] == "HIT" else "[red1]Failed[/red1]"
            age_field = result[3] if result[3] else "N/A"
            line = (
                pad_center(f"[{count}/{total_tasks}]", index_width) + Text(" | ") +
                pad_center(status_markup, status_width) + Text(" | ") +
                pad_center(result[0], country_width) + Text(" | ") +
                pad_center(result[1], dc_width) + Text(" | ") +
                pad_center(result[5], proxy_width) + Text(" | ") +
                pad_center(age_field, age_width)
            )
            console.print(line)

    console.print("\n[bold blue]Last cached (via HTTP proxies):[/bold blue]")
    for country, dc, status, age_str, url, proxy in sorted(results, key=lambda x: (x[0], x[1])):
        if status == "HIT":
            try:
                age_clean = age_str.replace("age:", "").strip()
                mins, secs = age_clean.split(":")
                age_verbose = f"{mins} mins {secs} seconds ago"
            except Exception:
                age_verbose = age_str if age_str else "N/A"
            dc_details = dc_colos.get(dc)
            if dc_details:
                city = dc_details.get("city", "")
                full_country = dc_details.get("country", country_map.get(country, country))
            else:
                city = ""
                full_country = country_map.get(country, country)
            console.print(f"{age_verbose} in {city}, {full_country}")

#################################
# TOR Check Mode – For each TOR exit node, a temporary TOR instance is spawned.
#################################
def check_tor_proxy(exit_node, url, socks_port, control_port, verbose=False):
    """
    Spawn a temporary TOR instance forcing the given exit node and use its SOCKS proxy to request the URL.
    Returns a tuple: (country, colo, status, age_str, url, label)
    """
    fingerprint = exit_node.get("fingerprint")
    country = exit_node.get("country", "??").upper()
    # Default colo using nickname if exactly 3 characters.
    nickname = exit_node.get("nickname", "")
    default_colo = nickname.upper() if len(nickname) == 3 else "N/A"
    temp_dir = tempfile.mkdtemp(prefix="tor_instance_")
    torrc_path = os.path.join(temp_dir, "torrc")
    torrc_contents = f"""\
SocksPort {socks_port} IsolateSOCKSAuth
ControlPort {control_port}
DataDirectory {temp_dir}
ExitNodes ${fingerprint}
StrictNodes 1
Log notice stdout
"""
    with open(torrc_path, "w") as f:
        f.write(torrc_contents)
    if verbose:
        console.log(f"[INFO] Starting TOR instance for exit node {fingerprint} ({country}) on SocksPort {socks_port} and ControlPort {control_port}.")
    try:
        proc = subprocess.Popen(["tor", "-f", torrc_path],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True)
    except Exception as e:
        console.log(f"[ERROR] Failed to start TOR for exit node {fingerprint}: {e}")
        shutil.rmtree(temp_dir)
        return (country, default_colo, "ERROR", "", url, f"TOR ({country})")
    bootstrapped = False
    try:
        for _ in range(30):
            line = proc.stdout.readline()
            if "Bootstrapped 100%" in line:
                bootstrapped = True
                break
            time.sleep(1)
    except Exception as e:
        console.log(f"[ERROR] Error during TOR bootstrap for {fingerprint}: {e}")
    if not bootstrapped:
        proc.terminate()
        proc.wait()
        shutil.rmtree(temp_dir)
        return (country, default_colo, "BOOTSTRAP FAILED", "", url, f"TOR ({country})")
    proxies = {
        "http": f"socks5h://127.0.0.1:{socks_port}",
        "https": f"socks5h://127.0.0.1:{socks_port}"
    }
    try:
        r = requests.get(url, proxies=proxies, timeout=15)
        r.raise_for_status()
        cf_status = r.headers.get("CF-Cache-Status", "") or r.headers.get("X-Cache", "")
        cf_status = cf_status.upper()
        # Attempt to extract colo from the X-Served-By header.
        x_served_by = r.headers.get("X-Served-By", "")
        if x_served_by:
            parts = [p.strip() for p in x_served_by.split(",")]
            last_part = parts[-1]
            if "-" in last_part:
                extracted_colo = last_part.split("-")[-1].strip().upper()
            else:
                extracted_colo = default_colo
        else:
            # Fall back to CF-Ray if available.
            cf_ray = r.headers.get("CF-Ray", "")
            if cf_ray and "-" in cf_ray:
                extracted_colo = cf_ray.split("-")[-1].strip().upper()
            else:
                extracted_colo = default_colo
        if "HIT" in cf_status:
            age_val = r.headers.get("Age", "")
            try:
                age_seconds = int(age_val)
                minutes = age_seconds // 60
                seconds = age_seconds % 60
                age_str = f"age: {minutes}:{seconds:02d}"
            except Exception:
                age_str = ""
            status = "HIT"
        else:
            status = "MISS"
            age_str = ""
    except Exception as e:
        if verbose:
            console.log(f"[ERROR] Request via TOR for exit node {fingerprint} failed: {e}")
        status = "REQUEST FAILED"
        age_str = ""
        extracted_colo = default_colo
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
    shutil.rmtree(temp_dir)
    return (country, extracted_colo, status, age_str, url, f"TOR ({country})")

#################################
# TOR Proxies Check Mode – Runs TOR tests concurrently with a limit.
#################################
def check_cache_for_all_tor_exit_nodes(url, verbose=False):
    try:
        r = requests.get("https://onionoo.torproject.org/details?flag=Exit", timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        console.log(f"[red1]Error fetching TOR exit nodes: {e}[/red1]")
        return
    exit_nodes = data.get("relays", [])
    total_nodes = len(exit_nodes)
    console.log(f"[bold cyan]Fetched {total_nodes} TOR exit nodes.[/bold cyan]")
    results = []
    max_tor_workers = 10  # Limit concurrent TOR processes
    base_socks_port = 9060
    base_control_port = 9061
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_tor_workers) as executor:
        future_to_node = {}
        for i, node in enumerate(exit_nodes):
            socks_port = base_socks_port + (i * 2)
            control_port = base_control_port + (i * 2)
            future = executor.submit(check_tor_proxy, node, url, socks_port, control_port, verbose)
            future_to_node[future] = node
        count = 0
        for future in concurrent.futures.as_completed(future_to_node):
            count += 1
            result = future.result()
            results.append(result)
            status_markup = "[green3]Success[/green3]" if result[2] == "HIT" else "[red1]Failed[/red1]"
            age_field = result[3] if result[3] else "N/A"
            line = (
                pad_center(f"[{count}/{total_nodes}]", 12) + Text(" | ") +
                pad_center(status_markup, 12) + Text(" | ") +
                pad_center(result[0], 10) + Text(" | ") +
                pad_center(result[1], 10) + Text(" | ") +
                pad_center(result[5], 28) + Text(" | ") +
                pad_center(age_field, 14)
            )
            console.print(line)
    console.print("\n[bold blue]TOR Exit Nodes Summary:[/bold blue]")
    for country, colo, status, age_str, url, label in sorted(results, key=lambda x: (x[0], x[1])):
        if status == "HIT":
            console.print(f"{country} ({colo}): {status}, {age_str}")
        else:
            console.print(f"{country} ({colo}): {status}")

#################################
# Main entry point using sub-commands.
#################################
def main():
    parser = argparse.ArgumentParser(
        description=(
            "Proxy scraper and Cloudflare cache checker.\n\n"
            "Subcommands:\n"
            "  scrape   Gather proxies from multiple sources and save/update a JSON file of validated proxies.\n"
            "  check    Check the cache status of a specified URL using proxies.\n\n"
            "For the check command, you can perform:\n"
            "  --http   Use HTTP proxies from an input file.\n"
            "  --tor    Fetch TOR exit nodes (from onionoo) and test each one by forcing TOR circuits.\n"
            "If both are specified, HTTP tests run first, then TOR tests."
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Sub-command to run")

    # Sub-command "scrape" (unchanged)
    scrape_parser = subparsers.add_parser(
        "scrape",
        help="Gather and test proxies, then save/update a JSON file of validated proxies.",
        description=(
            "Gather proxies from multiple sources (e.g. ProxyScrape, Free Proxy List, etc.), test them against "
            "Cloudflare's trace endpoint, and then save the working proxies to a JSON file (grouped by country and data center)."
        )
    )
    group = scrape_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-o", "--output", metavar="FILE", help="Output JSON file for validated proxies (overwrite mode).")
    group.add_argument("-add", metavar="FILE", help="Update an existing JSON file with new validated proxies (merge mode).")
    scrape_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output.")
    scrape_parser.add_argument("--show-missing", action="store_true", help="Print missing data centers after testing.")

    # Sub-command "check"
    check_parser = subparsers.add_parser(
        "check",
        help="Check the cache status of a specified URL using proxies.",
        description=(
            "Use proxies to check the cache status of a given URL. You can test using:\n"
            "  --http : Use HTTP proxies from an input file.\n"
            "  --tor  : Fetch TOR exit nodes (from onionoo) and test each one by forcing TOR circuits.\n"
            "If both are specified, HTTP tests run first, then TOR tests."
        )
    )
    check_parser.add_argument("-i", "--input", metavar="FILE", help="Input JSON file with validated HTTP proxies (required for --http).")
    check_parser.add_argument("-u", "--url", required=True, help="URL whose cache status should be checked.")
    check_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    check_parser.add_argument("--tor", action="store_true", help="Use TOR exit nodes (fetched from onionoo) for testing.")
    check_parser.add_argument("--http", action="store_true", help="Use HTTP proxies from the input file for testing.")

    args = parser.parse_args()

    if args.command == "scrape":
        sources = {
            "proxyscrape_http": {
                "url": "https://api.proxyscrape.com/?request=getproxies&proxytype=http",
                "parse_type": "text"
            },
            "proxyscrape_https": {
                "url": "https://api.proxyscrape.com/?request=getproxies&proxytype=https",
                "parse_type": "text"
            },
            "proxy_list_download_http": {
                "url": "https://www.proxy-list.download/api/v1/get?type=http",
                "parse_type": "text"
            },
            "proxy_list_download_https": {
                "url": "https://www.proxy-list.download/api/v1/get?type=https",
                "parse_type": "text"
            },
            "sslproxies": {
                "url": "https://www.sslproxies.org/",
                "parse_type": "html-ssl"
            },
            "free_proxy_list": {
                "url": "https://free-proxy-list.net/",
                "parse_type": "html-ssl"
            },
            "proxynova": {
                "url": "https://www.proxynova.com/proxy-server-list/",
                "parse_type": "proxynova"
            },
            "free_proxy_list_jsdelivr": {
                "url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
                "parse_type": "text"
            },
            "socks_list_http": {
                "url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
                "parse_type": "text"
            },
            "monosans_all": {
                "url": "https://raw.githubusercontent.com/monosans/proxy-list/refs/heads/main/proxies/all.txt",
                "parse_type": "text"
            },
            "monosans_anonymous": {
                "url": "https://raw.githubusercontent.com/monosans/proxy-list/refs/heads/main/proxies_anonymous/all.txt",
                "parse_type": "text"
            }
        }
        console.log("[bold blue]Gathering proxies from sources...[/bold blue]")
        proxies = gather_proxies(sources, verbose=args.verbose)
        total_proxies = len(proxies)
        console.log(f"[bold cyan]Total unique proxies found: {total_proxies}[/bold cyan]")

        working_proxies = {}
        count = 0
        index_width = 12
        status_width = 12
        proxy_width = 28
        country_width = 10
        dc_width = 10

        console.log("[bold blue]Testing HTTP proxies...[/bold blue]")
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(test_proxy, proxy): proxy for proxy in proxies}
            for future in concurrent.futures.as_completed(futures):
                count += 1
                proxy = futures[future]
                try:
                    proxy, success, loc, colo = future.result()
                except Exception:
                    success, loc, colo = False, None, None

                try:
                    ip, port = proxy.split(":", 1)
                except Exception:
                    ip, port = proxy, ""
                status_markup = "[green3]Success[/green3]" if success else "[red1]Failed[/red1]"
                index_text = pad_center(f"[{count}/{total_proxies}]", index_width)
                status_text = pad_center(status_markup, status_width)
                proxy_text = pad_center(f"{ip}:{port}", proxy_width)
                country_text = pad_center(loc or "", country_width)
                dc_text = pad_center(colo or "", dc_width)
                line = index_text + Text(" | ") + status_text + Text(" | ") + proxy_text + Text(" | ") + country_text + Text(" | ") + dc_text
                console.print(line)
                if success:
                    working_proxies.setdefault(loc, {})
                    working_proxies[loc].setdefault(colo, [])
                    if proxy not in working_proxies[loc][colo]:
                        working_proxies[loc][colo].append(proxy)

        try:
            with open("DC-Colos.json", "r") as f:
                dc_colos = json.load(f)
        except Exception as e:
            console.log(f"[red1]Error loading DC-Colos.json: {e}[/red1]")
            dc_colos = {}
        try:
            with open("country.json", "r") as f:
                country_map = json.load(f)
        except Exception as e:
            console.log(f"[red1]Error loading country.json: {e}[/red1]")
            country_map = {}

        group_by_country = {}
        for dc, details in dc_colos.items():
            cca2 = details.get("cca2", "").upper()
            if cca2:
                group_by_country.setdefault(cca2, []).append(dc)

        final_proxies = {}
        for country_code in country_map:
            if country_code in group_by_country:
                final_proxies[country_code] = {}
                for dc in group_by_country[country_code]:
                    final_proxies[country_code][dc] = working_proxies.get(country_code, {}).get(dc, [])
            else:
                final_proxies[country_code] = {}

        missing_by_country = {}
        for country_code, dc_list in group_by_country.items():
            missing = []
            for dc in dc_list:
                if country_code not in working_proxies or dc not in working_proxies[country_code] or len(working_proxies[country_code][dc]) == 0:
                    missing.append(dc)
            if missing:
                country_name = country_map.get(country_code, country_code)
                missing_by_country[country_name] = missing

        if args.show_missing:
            if missing_by_country:
                console.print("\n[bold yellow]Missing:[/bold yellow]")
                for country, dcs in missing_by_country.items():
                    console.print(f"{country}: {', '.join(dcs)}")
            else:
                console.log("[bold green]All data centers have at least one working proxy.[/bold green]")

        if args.add:
            output_file = args.add
            try:
                with open(output_file, "r") as f:
                    existing = json.load(f)
            except Exception:
                existing = {}
            merged = merge_proxies(existing, final_proxies)
            with open(output_file, "w") as f:
                json.dump(merged, f, indent=4)
            console.log(f"[bold green]Working proxies updated in {output_file}[/bold green]")
        else:
            output_file = args.output
            with open(output_file, "w") as f:
                json.dump(final_proxies, f, indent=4)
            console.log(f"[bold green]Working proxies saved to {output_file}[/bold green]")

    elif args.command == "check":
        url = args.url
        run_http = args.http or (not args.tor)
        run_tor = args.tor

        if run_http:
            if not args.input:
                console.log("[red1]HTTP check requires an input file![/red1]")
                return
            console.log("[bold blue]Checking cache via HTTP proxies...[/bold blue]")
            check_cache_for_all_http(args.input, url, verbose=args.verbose)
        if run_tor:
            console.log("[bold blue]Checking cache via TOR exit nodes...[/bold blue]\n[bold red1]WARNING: This will be slow![/bold red1]")
            check_cache_for_all_tor_exit_nodes(url, verbose=args.verbose)

if __name__ == "__main__":
    main()
