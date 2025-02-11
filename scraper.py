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
from rich.console import Console
from rich.text import Text
from bs4 import BeautifulSoup

console = Console()

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
    # Remove schemes like "http://", "https://", "socks5://"
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

def test_proxy(proxy):
    proxy_url = f"http://{proxy}"
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        r = requests.get("https://cloudflare.com/cdn-cgi/trace", proxies=proxies, timeout=10)
        r.raise_for_status()
        data = {}
        for line in r.text.splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                data[key.strip()] = value.strip()
        if 'colo' in data and 'loc' in data:
            return (proxy, True, data['loc'], data['colo'])
        else:
            return (proxy, False, None, None)
    except Exception:
        return (proxy, False, None, None)

def pad_center(markup: str, width: int) -> Text:
    text = Text.from_markup(markup)
    current_width = text.cell_len
    if current_width < width:
        total_padding = width - current_width
        left_padding = total_padding // 2
        right_padding = total_padding - left_padding
        text = Text(" " * left_padding) + text + Text(" " * right_padding)
    return text

def merge_proxies(existing: dict, new: dict) -> dict:
    """Merge new proxy entries into an existing proxy JSON structure."""
    for country, dc_dict in new.items():
        if country not in existing:
            existing[country] = dc_dict
        else:
            for dc, proxy_list in dc_dict.items():
                if dc not in existing[country]:
                    existing[country][dc] = proxy_list
                else:
                    for proxy in proxy_list:
                        if proxy not in existing[country][dc]:
                            existing[country][dc].append(proxy)
    return existing

#################################
# The "check" mode: use validated proxies to test cache status.
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
        console.log(f"[blue]Request: GET {url}[/blue]")
        console.log(f"[blue]Using proxy: {proxy}[/blue]")
        console.log(f"[blue]Request Headers: {headers}[/blue]")
        console.log(f"[blue]Proxy settings: {proxies}[/blue]")
    try:
        r = requests.get(url, proxies=proxies, headers=headers, timeout=10)
        r.raise_for_status()
        if verbose:
            console.log(f"[green]Response Status: {r.status_code}[/green]")
            console.log(f"[green]Response Headers: {r.headers}[/green]")
        # Try CF-Cache-Status; if not present, use X-Cache.
        cf_status = r.headers.get("CF-Cache-Status", "")
        if not cf_status:
            cf_status = r.headers.get("X-Cache", "")
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

def check_cache_for_all(input_file, url, verbose=False):
    try:
        with open(input_file, "r") as f:
            validated = json.load(f)
    except Exception as e:
        console.log(f"[red1]Error loading validated proxies from {input_file}: {e}[/red1]")
        return

    # Also load DC-Colos.json and country.json for detailed location info.
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

    # Build tasks: one per (country, dc) pair using the first proxy from each group.
    tasks = []
    for country, dc_dict in validated.items():
        for dc, proxy_list in dc_dict.items():
            if proxy_list:
                tasks.append((country, dc, proxy_list[0]))

    total_tasks = len(tasks)
    results = []
    count = 0
    # Incremental output widths
    index_width = 12
    status_width = 12
    proxy_width = 28
    country_width = 10
    dc_width = 10

    console.log("[bold blue]Finding file in cache...[/bold blue]")
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
            line = (
                pad_center(f"[{count}/{total_tasks}]", index_width) + Text(" | ") +
                pad_center(status_markup, status_width) + Text(" | ") +
                pad_center(result[0], country_width) + Text(" | ") +
                pad_center(result[1], dc_width) + Text(" | ") +
                pad_center(result[5], proxy_width) + Text(" | ") +
                pad_center(result[4], 60)
            )
            console.print(line)

    # Now print a final summary for HIT proxies.
    console.print("\n[bold blue]Last cached:[/bold blue]")
    for country, dc, status, age_str, url, proxy in sorted(results, key=lambda x: (x[0], x[1])):
        if status == "HIT" and age_str:
            # Convert "age: M:SS" into "M mins SS seconds ago"
            try:
                age_clean = age_str.replace("age:", "").strip()
                mins, secs = age_clean.split(":")
                age_verbose = f"{mins} mins {secs} seconds ago"
            except Exception:
                age_verbose = age_str
            # Look up detailed location information from DC-Colos.json.
            dc_details = dc_colos.get(dc)
            if dc_details:
                city = dc_details.get("city", "")
                full_country = dc_details.get("country", country_map.get(country, country))
            else:
                city = ""
                full_country = country_map.get(country, country)
            console.print(f"{age_verbose} in {city}, {full_country}")

#################################
# Main entry point using sub-commands.
#################################
def main():
    parser = argparse.ArgumentParser(
        description=(
            "Proxy scraper and Cloudflare cache checker.\n\n"
            "Subcommands:\n"
            "  scrape   Gather proxies from multiple sources, test them against Cloudflare's trace endpoint, "
            "and save or update a JSON file with validated proxies. The validated proxies are grouped by country "
            "and data center (colo). Additional options let you display verbose debugging output and show missing data centers.\n\n"
            "  check    Use validated proxies (saved in a JSON file) to check the cache status of a specified URL. "
            "For each country/data center group, one proxy is used to send a GET request to the specified URL. "
            "The script then prints whether the cache was a HIT (including the Age converted to mm:ss) or a MISS, "
            "and finally prints a summary of the last cached times for proxies that returned HIT.\n\n"
            "Usage examples:\n"
            "  python3 scraper.py scrape -o validated-proxies.json\n"
            "  python3 scraper.py scrape -add validated-proxies.json --verbose --show-missing\n"
            "  python3 scraper.py check -i validated-proxies.json -u https://github.githubassets.com/favicons/favicon.png -v"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Sub-command to run")

    # Sub-command "scrape"
    scrape_parser = subparsers.add_parser(
        "scrape",
        help="Gather and test proxies, then save (or update) a JSON file of validated proxies.",
        description=(
            "Gather proxies from multiple sources (e.g. ProxyScrape, Free Proxy List, ProxyNova, etc.), test them against "
            "Cloudflare's trace endpoint, and then save the working proxies to a JSON file. The JSON file is structured as:\n\n"
            "  { country_code: { data_center: [proxy, ...], ... }, ... }\n\n"
            "Options:\n"
            "  -o, --output      Output JSON file to save validated proxies. (Overwrite mode.)\n"
            "  -add              Update (merge into) an existing JSON file with new validated proxies.\n"
            "  -v, --verbose     Enable verbose (debug) output showing all found proxies and processing details.\n"
            "  --show-missing    After testing, print a list of Cloudflare data centers (by country) that have no working proxy."
        )
    )
    group = scrape_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-o", "--output", metavar="FILE", help="Output JSON file for validated proxies (overwrite mode).")
    group.add_argument("-add", metavar="FILE", help="Update an existing JSON file with new validated proxies (merge mode).")
    scrape_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output.")
    scrape_parser.add_argument("--show-missing", action="store_true", help="Print missing Cloudflare data centers after testing.")

    # Sub-command "check"
    check_parser = subparsers.add_parser(
        "check",
        help="Check Cloudflare cache status using validated proxies.",
        description=(
            "Use a JSON file of validated proxies (generated in 'scrape' mode) to check the cache status of a given URL. "
            "For each country/data center group with at least one proxy, the script uses the first proxy to send a GET request "
            "to the specified URL. It then inspects Cloudflare headers to determine whether the cached copy was a HIT and how old it is. "
            "Incremental output is printed line-by-line, and after all tests a final summary (\"Last cached:\") is printed.\n\n"
            "Options:\n"
            "  -i, --input   Input JSON file containing validated proxies.\n"
            "  -u, --url     URL to check the cache status of.\n"
            "  -v, --verbose Enable verbose output (showing full request and response details)."
        )
    )
    check_parser.add_argument("-i", "--input", metavar="FILE", required=True, help="Input JSON file with validated proxies.")
    check_parser.add_argument("-u", "--url", required=True, help="URL whose cache status should be checked.")
    check_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")

    args = parser.parse_args()

    if args.command == "scrape":
        # --- SCRAPE MODE ---
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

        console.log("[bold blue]Finding file in cache...[/bold blue]")
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

        # Merge if update mode (-add) is chosen.
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
        # --- CHECK MODE ---
        input_file = args.input
        url = args.url
        check_cache_for_all(input_file, url, verbose=args.verbose)

if __name__ == "__main__":
    main()
