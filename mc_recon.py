#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════╗
║          MINECRAFT SERVER REAL IP DETECTION TOOL            ║
║          Advanced Reconnaissance & Firewall Bypass          ║
║                                                              ║
║  Metode: DNS Enum, SRV Lookup, Historical DNS, Subdomain   ║
║  Bruteforce, Shodan/Censys, Protocol Handshake, SSL/TLS    ║
║  Certificate Transparency, Port Scan, Firewall Detection    ║
╚════════════════════════════════╝
"""

import socket
import struct
import json
import sys
import os
import ssl
import time
import hashlib
import subprocess
import re
import argparse
import concurrent.futures
from datetime import datetime
from typing import Optional, List, Dict, Tuple, Set

# === Third Party ===
try:
    import dns.resolver
    import dns.reversename
    import dns.zone
    import dns.query
except ImportError:
    print("[!] Install dnspython: pip install dnspython")

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] Install requests: pip install requests")

try:
    from mcstatus import JavaServer, BedrockServer
except ImportError:
    print("[!] Install mcstatus: pip install mcstatus")

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    R = Fore.RED; G = Fore.GREEN; C = Fore.CYAN; Y = Fore.YELLOW
    M = Fore.MAGENTA; W = Fore.WHITE; B = Fore.BLUE; RST = Style.RESET_ALL
except ImportError:
    R = G = C = Y = M = W = B = RST = ""

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    x509 = None

try:
    import nmap
except ImportError:
    nmap = None


# ================================================================
#                      GLOBAL CONFIG
# ================================================================
VERSION = "3.0"
TIMEOUT = 5
MC_DEFAULT_PORT = 25565
MC_BEDROCK_PORT = 19132
MAX_THREADS = 50

BANNER = f"""
{C}╔════════════════════════════════╗
║{W}  ███╗   ███╗ ██████╗    ██████╗ ██████╗ ████╗ ███╗  {C}║
║{W}  ████╗ ████║██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔══██╗████║ {C}║
║{W}  ██╔████╔██║██║         ██████╔╝████╗  ██║     ██║   ██║██╔██║{C}║
║{W}  ██║╚██╔╝██║██║         ██╔══██╗██╔══╝  ██║     ██║   ██║██║  {C}║
║{W}  ██║ ╚═╝ ██║╚██████╗   ██║████╗╚██████╗╚██████╔╝██║  {C}║
║{W}  ╚═╝     ╚═╝ ╚═════╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝ {C}║
║{Y}        Minecraft Server Real IP Detection Tool v{VERSION}            {C}║
║{M}           Advanced Recon & Firewall Analysis                     {C}║
╚════════════════════════════════╝{RST}
"""

# Known Minecraft protection/proxy services
KNOWN_PROTECTIONS = {
    "tcpshield": ["tcpshield.com", "104.16.", "172.67."],
    "cosmicguard": ["cosmicguard.com"],
    "nexusguard": ["nexusguard.com"],
    "cloudflare": ["cloudflare.com", "104.16.", "104.17.", "104.18.", "104.19.",
                   "104.20.", "104.21.", "104.22.", "104.23.", "104.24.",
                   "172.67.", "173.245.", "103.21.", "103.22.", "103.31.",
                   "141.101.", "108.162.", "190.93.", "188.114.", "197.234.",
                   "198.41.", "162.158."],
    "ddos-guard": ["ddos-guard.net", "186.2."],
    "ovh_game_ddos": ["ovh.net", "ovh.com", "51.79.", "51.81.", "51.89.",
                       "51.91.", "51.161.", "51.178.", "51.195.", "51.210.",
                       "51.222.", "139.99.", "142.44.", "144.217.", "149.56.",
                       "158.69.", "167.114.", "192.95.", "198.27.", "198.50.",
                       "198.100.", "209.141."],
    "path.net": ["path.net"],
    "voxility": ["voxility.com", "voxility.net"],
    "blazingfast": ["blazingfast.io"],
    "javapipe": ["javapipe.com"],
    "corero": ["corero.com"],
    "akamai": ["akamai.com", "akamai.net", "23."],
    "sucuri": ["sucuri.net"],
    "incapsula": ["incapsula.com", "imperva.com"],
    "bungeeguard": ["bungeeguard"],
    "velocity": ["velocity"],
    "waterfall": ["waterfall"],
    "bungeecord": ["bungeecord"],
}

# Subdomain wordlist for MC servers
MC_SUBDOMAINS = [
    "play", "mc", "hub", "lobby", "proxy", "bungee", "velocity", "gate",
    "server", "games", "pvp", "survival", "creative", "skyblock",
    "factions", "prison", "kitpvp", "bedwars", "skywars", "practice",
    "node1", "node2", "node3", "node4", "node5",
    "us", "eu", "asia", "na", "sa", "au",
    "backend", "back", "origin", "real", "direct", "raw", "actual",
    "panel", "pterodactyl", "ptero", "admin", "cp", "control",
    "web", "www", "api", "map", "dynmap", "bluemap", "live",
    "ts", "ts3", "teamspeak", "discord", "vote", "store", "shop",
    "mail", "smtp", "imap", "pop", "mx", "ftp", "sftp", "ssh",
    "dev", "test", "staging", "beta", "alpha", "old", "new",
    "db", "database", "mysql", "redis", "mongo",
    "cdn", "static", "media", "files", "download",
    "vpn", "openvpn", "wireguard",
    "ns1", "ns2", "dns1", "dns2",
    "proxy1", "proxy2", "proxy3",
    "bungee1", "bungee2", "bungee3",
    "lobby1", "lobby2", "lobby3",
    "hub1", "hub2", "hub3",
    "sv1", "sv2", "sv3", "sv4", "sv5",
    "s1", "s2", "s3", "s4", "s5",
    "vps", "vps1", "vps2", "vps3",
    "dedi", "dedi1", "dedi2",
    "host", "hosting",
]


# ================================================================
#                      UTILITY FUNCTIONS
# ================================================================

def print_header(text: str):
    width = 60
    print(f"\n{C}{'═' * width}")
    print(f"  {Y}▶ {W}{text}")
    print(f"{C}{'═' * width}{RST}")


def print_found(text: str):
    print(f"  {G}[✓]{W} {text}{RST}")


def print_info(text: str):
    print(f"  {C}[i]{W} {text}{RST}")


def print_warn(text: str):
    print(f"  {Y}[!]{W} {text}{RST}")


def print_fail(text: str):
    print(f"  {R}[✗]{W} {text}{RST}")


def print_result(label: str, value: str):
    print(f"  {M}[→]{W} {label}: {G}{value}{RST}")


def is_private_ip(ip: str) -> bool:
    """Check if IP is private/reserved"""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_reserved or addr.is_loopback
    except ValueError:
        return False


def resolve_ip(domain: str) -> Optional[str]:
    """Basic A record resolution"""
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return str(answers[0])
    except Exception:
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None


def get_session() -> requests.Session:
    """Create a requests session with retries"""
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    })
    return session


# ================================================================
#              MODULE 1: DNS DEEP ENUMERATION
# ================================================================

class DNSEnumerator:
    """Comprehensive DNS enumeration for Minecraft servers"""

    def __init__(self, domain: str):
        self.domain = domain
        self.results = {}
        self.all_ips = set()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = TIMEOUT
        self.resolver.lifetime = TIMEOUT
        # Use multiple DNS servers for cross-referencing
        self.dns_servers = [
            '8.8.8.8', '8.8.4.4',           # Google
            '1.1.1.1', '1.0.0.1',           # Cloudflare
            '9.9.9', '149.112.112.112',   # Quad9
            '208.67.222.222', '208.67.220.220',  # OpenDNS
            '76.76.2.0', '76.76.10.0',      # ControlD
        ]

    def run_all(self) -> Dict:
        print_header("MODULE 1: DNS Deep Enumeration")

        self._resolve_a_records()
        self._resolve_aaaa_records()
        self._resolve_srv_records()
        self._resolve_mx_records()
        self._resolve_txt_records()
        self._resolve_ns_records()
        self._resolve_soa_records()
        self._resolve_cname_records()
        self._resolve_caa_records()
        self._cross_dns_check()
        self._check_dns_any()

        return {"dns_results": self.results, "all_ips": list(self.all_ips)}

    def _resolve_a_records(self):
        print_info("Resolving A records...")
        try:
            answers = dns.resolver.resolve(self.domain, 'A')
            ips = [str(rdata) for rdata in answers]
            self.results['A'] = ips
            for ip in ips:
                self.all_ips.add(ip)
                print_found(f"A Record: {ip}")
        except Exception as e:
            print_fail(f"A Record: {e}")

    def _resolve_aaaa_records(self):
        print_info("Resolving AAAA records...")
        try:
            answers = dns.resolver.resolve(self.domain, 'AAAA')
            ips = [str(rdata) for rdata in answers]
            self.results['AAAA'] = ips
            for ip in ips:
                print_found(f"AA Record: {ip}")
        except Exception as e:
            print_fail(f"AA Record: {e}")

    def _resolve_srv_records(self):
        """Critical for Minecraft - SRV records often leak real IP"""
        print_info("Resolving SRV records (_minecraft._tcp)...")
        srv_queries = [
            f'_minecraft._tcp.{self.domain}',
            f'_minecraft._udp.{self.domain}',  # Bedrock
        ]
        for srv_domain in srv_queries:
            try:
                answers = dns.resolver.resolve(srv_domain, 'SRV')
                for rdata in answers:
                    target = str(rdata.target).rstrip('.')
                    port = rdata.port
                    priority = rdata.priority
                    weight = rdata.weight
                print_found(f"SRV: {srv_domain}")
                    print_result("  Target", target)
                    print_result("  Port", str(port))
                    print_result("  Priority", str(priority))
                    print_result("  Weight", str(weight))

                    # Resolve the SRV target
                    target_ip = resolve_ip(target)
                    if target_ip:
                        self.all_ips.add(target_ip)
                        print_found(f"  SRV Target IP: {target_ip}")
                self.results['SRV_TARGET_IP'] = target_ip

                self.results['SRV'] = {
                        'target': target,
                        'port': port,
                        'priority': priority,
                        'weight': weight
                    }
            except Exception as e:
                print_fail(f"SRV ({srv_domain}): {e}")

    def _resolve_mx_records(self):
        """MX records sometimes point to same server"""
        print_info("Resolving MX records...")
        try:
            answers = dns.resolver.resolve(self.domain, 'MX')
            mx_list = []
            for rdata in answers:
                mx_host = str(rdata.exchange).rstrip('.')
                pref = rdata.preference
                mx_ip = resolve_ip(mx_host)
                mx_list.append({'host': mx_host, 'preference': pref, 'ip': mx_ip})
                print_found(f"MX: {mx_host} (pref: {pref})")
                if mx_ip:
                    self.all_ips.add(mx_ip)
                    print_result("  MX IP", mx_ip)
            self.results['MX'] = mx_list
        except Exception as e:
            print_fail(f"MX Record: {e}")

    def _resolve_txt_records(self):
        """TXT records may contain SPF with IP ranges"""
        print_info("Resolving TXT records (SPF/DKIM/DMARC)...")
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            txt_list = []
            for rdata in answers:
                txt = str(rdata).strip('"')
                txt_list.append(txt)
                print_found(f"TXT: {txt[:100]}...")

                # Extract IPs from SPF records
                if 'v=spf1' in txt:
                    ip_matches = re.findall(
                        r'ip[46]:([0-9a-fA-F.:\/]+)', txt
                    )
                    for ip in ip_matches:
                        clean_ip = ip.split('/')[0]
                        self.all_ips.add(clean_ip)
                        print_found(f"  SPF IP Found: {clean_ip}")

                    # Check 'a' and 'include' mechanisms
                    includes = re.findall(r'include:(\S+)', txt)
                    for inc in includes:
                        print_info(f"  SPF Include: {inc}")
                inc_ip = resolve_ip(inc)
                        if inc_ip:
                            self.all_ips.add(inc_ip)
                            print_found(f"  SPF Include IP: {inc_ip}")

            self.results['TXT'] = txt_list
        except Exception as e:
            print_fail(f"TXT Record: {e}")

        # DMARC
        try:
            dmarc_answers = dns.resolver.resolve(f'_dmarc.{self.domain}', 'TXT')
            for rdata in dmarc_answers:
                print_found(f"DMARC: {str(rdata)}")
        except Exception:
            pass

    def _resolve_ns_records(self):
        print_info("Resolving NS records...")
        try:
            answers = dns.resolver.resolve(self.domain, 'NS')
            ns_list = []
            for rdata in answers:
                ns = str(rdata).rstrip('.')
                ns_ip = resolve_ip(ns)
                ns_list.append({'ns': ns, 'ip': ns_ip})
                print_found(f"NS: {ns} → {ns_ip}")
            self.results['NS'] = ns_list
        except Exception as e:
            print_fail(f"NS Record: {e}")

    def _resolve_soa_records(self):
        print_info("Resolving SOA records...")
        try:
            answers = dns.resolver.resolve(self.domain, 'SOA')
            for rdata in answers:
                mname = str(rdata.mname).rstrip('.')
                rname = str(rdata.rname).rstrip('.')
                serial = rdata.serial
                print_found(f"SOA MNAME: {mname}")
                print_found(f"SOA RNAME: {rname}")
                print_found(f"SOA Serial: {serial}")

                mname_ip = resolve_ip(mname)
                if mname_ip:
                    self.all_ips.add(mname_ip)
                print_found(f"SOA MNAME IP: {mname_ip}")

                self.results['SOA'] = {
                    'mname': mname, 'rname': rname, 'serial': serial
                }
        except Exception as e:
            print_fail(f"SOA Record: {e}")

    def _resolve_cname_records(self):
        print_info("Resolving CNAME records...")
        try:
            answers = dns.resolver.resolve(self.domain, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target).rstrip('.')
                print_found(f"CNAME: {cname}")
                cname_ip = resolve_ip(cname)
                if cname_ip:
                    self.all_ips.add(cname_ip)
                    print_found(f"CNAME IP: {cname_ip}")
                self.results['CNAME'] = cname
        except Exception:
            pass

    def _resolve_caa_records(self):
        print_info("Resolving CAA records...")
        try:
            answers = dns.resolver.resolve(self.domain, 'CAA')
            for rdata in answers:
                print_found(f"CAA: {rdata}")
        except Exception:
            pass

    def _cross_dns_check(self):
        """Query multiple DNS servers to find inconsistencies"""
        print_info("Cross-referencing with multiple DNS servers...")
        cross_results = {}
        for dns_server in self.dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 3
                resolver.lifetime = 3
                answers = resolver.resolve(self.domain, 'A')
                ips = [str(r) for r in answers]
                cross_results[dns_server] = ips
                for ip in ips:
                    self.all_ips.add(ip)
            except Exception:
                continue

        # Find inconsistencies
        all_cross_ips = set()
        for dns_srv, ips in cross_results.items():
            for ip in ips:
                all_cross_ips.add(ip)

        if len(all_cross_ips) > 1:
            print_warn(f"DNS Inconsistency detected! Multiple IPs found:")
            for ip in all_cross_ips:
                print_result("  IP", ip)
        else:
            print_info(f"All DNS servers return consistent results")

        self.results['cross_dns'] = cross_results

    def _check_dns_any(self):
        """Try ANY query (often blocked but worth trying)"""
        print_info("Attempting DNS ANY query...")
        try:
            answers = dns.resolver.resolve(self.domain, 'ANY')
            for rdata in answers:
                print_found(f"ANY: {rdata.rdtype.name} → {rdata}")
        except Exception:
            print_info("ANY query blocked (normal)")


# ================================================================
#          MODULE 2: SUBDOMAIN ENUMERATION & BRUTEFORCE
# ================================================================

class SubdomainEnumerator:
    """Find subdomains that may leak the real IP"""

    def __init__(self, domain: str):
        self.domain = domain
        self.found_subdomains = {}
        self.all_ips = set()

    def run_all(self) -> Dict:
        print_header("MODULE 2: Subdomain Enumeration")

        self._bruteforce_subdomains()
        self._crtsh_lookup()
        self._hackertarget_lookup()
        self._threatcrowd_lookup()
        self._rapiddns_lookup()

        return {"subdomains": self.found_subdomains, "all_ips": list(self.all_ips)}

    def _bruteforce_subdomains(self):
        print_info(f"Bruteforcing {len(MC_SUBDOMAINS)} MC-specific subdomains...")

        def check_subdomain(sub):
            fqdn = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                return (fqdn, ip)
            except socket.gaierror:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in MC_SUBDOMAINS}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    fqdn, ip = result
                self.found_subdomains[fqdn] = ip
                    self.all_ips.add(ip)
                    print_found(f"{fqdn} → {ip}")

        print_info(f"Found {len(self.found_subdomains)} subdomains via bruteforce")

    def _crtsh_lookup(self):
        """Certificate Transparency logs via crt.sh"""
        print_info("Querying crt.sh (Certificate Transparency)...")
        try:
            session = get_session()
            resp = session.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                seen = set()
                for entry in data:
                    name = entry.get('name_value', '')
                    for line in name.split('\n'):
                        line = line.strip().lower()
                        if line and '*' not in line and line not in seen:
                            seen.add(line)
                            try:
                                ip = socket.gethostbyname(line)
                                if line not in self.found_subdomains:
                                    self.found_subdomains[line] = ip
                                    self.all_ips.add(ip)
                                    print_found(f"crt.sh: {line} → {ip}")
                            except socket.gaierror:
                                pass
                print_info(f"crt.sh returned {len(seen)} unique names")
        except Exception as e:
            print_fail(f"crt.sh error: {e}")

    def _hackertarget_lookup(self):
        print_info("Querying HackerTarget...")
        try:
            session = get_session()
            resp = session.get(
                f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
                timeout=10
            )
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.strip().split('\n'):
                    if ',' in line:
                        host, ip = line.split(',', 1)
                        host = host.strip().lower()
                        ip = ip.strip()
                        if host not in self.found_subdomains:
                            self.found_subdomains[host] = ip
                            self.all_ips.add(ip)
                            print_found(f"HackerTarget: {host} → {ip}")
        except Exception as e:
            print_fail(f"HackerTarget error: {e}")

    def _threatcrowd_lookup(self):
        print_info("Querying ThreatCrowd...")
        try:
            session = get_session()
            resp = session.get(
                f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                subs = data.get('subdomains', [])
                for sub in subs:
                    sub = sub.strip().lower()
                    if sub not in self.found_subdomains:
                        try:
                            ip = socket.gethostbyname(sub)
                            self.found_subdomains[sub] = ip
                            self.all_ips.add(ip)
                            print_found(f"ThreatCrowd: {sub} → {ip}")
                        except socket.gaieror:
                            pass
        except Exception as e:
            print_fail(f"ThreatCrowd error: {e}")

    def _rapiddns_lookup(self):
        print_info("Querying RapidDNS...")
        try:
            session = get_session()
            resp = session.get(
                f"https://rapiddns.io/subdomain/{self.domain}?full=1",
                timeout=10
            )
            if resp.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, 'html.parser')
                table = soup.find('table')
                if table:
                    rows = table.find_all('tr')[1:]  # skip header
                    for row in rows:
                        cols = row.find_all('td')
                        if len(cols) >= 3:
                            subdomain = cols[0].text.strip().lower()
                            ip = cols[2].text.strip()
                            if subdomain not in self.found_subdomains:
                                self.found_subdomains[subdomain] = ip
                                self.all_ips.add(ip)
                                print_found(f"RapidDNS: {subdomain} → {ip}")
        except Exception as e:
            print_fail(f"RapidDNS error: {e}")


# ================================================================
#          MODULE 3: HISTORICAL DNS LOOKUP
# ================================================================

class HistoricalDNS:
    """Find old DNS records that may reveal the real IP before protection"""

    def __init__(self, domain: str):
        self.domain = domain
        self.historical_ips = set()

    def run_all(self) -> Dict:
        print_header("MODULE 3: Historical DNS Records")

        self._securitytrails_lookup()
        self._viewdns_lookup()
        self._completedns_lookup()
        self._dnshistory_lookup()
        self._whoisxml_lookup()

        return {"historical_ips": list(self.historical_ips)}

    def _securitytrails_lookup(self):
        """SecurityTrails historical DNS"""
        print_info("Querying SecurityTrails (historical A records)...")
        try:
            session = get_session()
            # Public page scraping (no API key needed)
            resp = session.get(
                f"https://securitytrails.com/domain/{self.domain}/history/a",
                timeout=10
            )
            if resp.status_code == 200:
                # Extract IPs from page
                ip_pattern = re.findall(
                    r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp.text
                )
                seen = set()
                for ip in ip_pattern:
                    if ip not in seen and not ip.startswith('0.'):
                        seen.add(ip)
                        self.historical_ips.add(ip)
                        print_found(f"SecurityTrails Historical: {ip}")
            else:
                print_warn("SecurityTrails requires browser/API key for full access")
        except Exception as e:
            print_fail(f"SecurityTrails error: {e}")

    def _viewdns_lookup(self):
        """ViewDNS.info IP history"""
        print_info("Querying ViewDNS.info (IP History)...")
        try:
            session = get_session()
            resp = session.get(
                f"https://viewdns.info/iphistory/?domain={self.domain}",
                timeout=10
            )
            if resp.status_code == 200:
                ip_pattern = re.findall(
                    r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp.text
                )
                seen = set()
                for ip in ip_pattern:
                if ip not in seen and not ip.startswith('0.'):
                        seen.add(ip)
                        self.historical_ips.add(ip)
                        print_found(f"ViewDNS Historical: {ip}")
        except Exception as e:
            print_fail(f"ViewDNS error: {e}")

    def _completedns_lookup(self):
        print_info("Querying CompleteDNS...")
        try:
            session = get_session()
            resp = session.get(
                f"https://completedns.com/dns-history/{self.domain}",
                timeout=10
            )
            if resp.status_code == 200:
                ip_pattern = re.findall(
                    r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp.text
                )
                for ip in set(ip_pattern):
                    if not ip.startswith('0.'):
                        self.historical_ips.add(ip)
                print_found(f"CompleteDNS Historical: {ip}")
        except Exception as e:
            print_fail(f"CompleteDNS error: {e}")

    def _dnshistory_lookup(self):
        print_info("Querying DNSHistory.org...")
        try:
            session = get_session()
            resp = session.get(
                f"https://dnshistory.org/dns-records/{self.domain}",
                timeout=10
            )
            if resp.status_code == 200:
                ip_pattern = re.findall(
                    r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp.text
                )
                for ip in set(ip_pattern):
                    if not ip.startswith('0.'):
                        self.historical_ips.add(ip)
                        print_found(f"DNSHistory: {ip}")
        except Exception as e:
            print_fail(f"DNSHistory error: {e}")

    def _whoisxml_lookup(self):
        print_info("Querying WhoisXML API (free tier)...")
        try:
            session = get_session()
            resp = session.get(
                f"https://dns-history.whoisxmlapi.com/api/v1?apiKey=at_demo&domainName={self.domain}&type=A",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                records = data.get('result', [])
                for record in records:
                    ip = record.get('value', '')
                    if ip:
                        self.historical_ips.add(ip)
                first_seen = record.get('first_seen', 'N/A')
                        last_seen = record.get('last_seen', 'N/A')
                        print_found(f"WhoisXML: {ip} (first: {first_seen}, last: {last_seen})")
        except Exception as e:
            print_fail(f"WhoisXML error: {e}")


# ================================================================
#       MODULE 4: MINECRAFT PROTOCOL HANDSHAKE & STATUS
# ================================================================

class MinecraftProbe:
    """Direct Minecraft protocol interaction to extract server info"""

    def __init__(self, domain: str, port: int = MC_DEFAULT_PORT):
        self.domain = domain
        self.port = port

    def run_all(self) -> Dict:
        print_header("MODULE 4: Minecraft Protocol Probe")

        results = {}
        results['java_status'] = self._java_server_status()
        results['bedrock_status'] = self._bedrock_server_status()
        results['raw_handshake'] = self._raw_handshake()
        results['port_scan'] = self._scan_mc_ports()
        results['ping_analysis'] = self._ping_analysis()

        return results

    def _java_server_status(self) -> Optional[Dict]:
        """Query Java Edition server status"""
        print_info(f"Querying Java server status ({self.domain}:{self.port})...")
        try:
            server = JavaServer.lookup(f"{self.domain}:{self.port}")
            status = server.status()

            info = {
                'version': status.version.name if status.version else 'Unknown',
                'protocol': status.version.protocol if status.version else 0,
                'players_online': status.players.online if status.players else 0,
                'players_max': status.players.max if status.players else 0,
                'description': str(status.description) if status.description else '',
                'latency': round(status.latency, 2),
                'favicon': bool(status.favicon) if hasattr(status, 'favicon') else False,
            }

            # Player sample (may contain useful info)
            if status.players and status.players.sample:
                info['player_sample'] = [
                    {'name': p.name, 'uuid': str(p.id)}
                    for p in status.players.sample
                ]

            print_found(f"Server Version: {info['version']}")
            print_found(f"Protocol: {info['protocol']}")
            print_found(f"Players: {info['players_online']}/{info['players_max']}")
            print_found(f"Latency: {info['latency']}ms")
            print_found(f"MOTD: {info['description'][:80]}")

            # Analyze MOTD for IP leaks
            motd = info['description']
            ip_in_motd = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', motd)
            if ip_in_motd:
                print_warn(f"IP found in MOTD: {ip_in_motd}")
                info['motd_ips'] = ip_in_motd

            return info

        except Exception as e:
            print_fail(f"Java status error: {e}")
            return None

    def _bedrock_server_status(self) -> Optional[Dict]:
        """Query Bedrock Edition server status"""
        print_info(f"Querying Bedrock server ({self.domain}:{MC_BEDROCK_PORT})...")
        try:
            server = BedrockServer.lookup(f"{self.domain}:{MC_BEDROCK_PORT}")
            status = server.status()

            info = {
                'motd': str(status.motd) if status.motd else '',
                'version': status.version.name if status.version else 'Unknown',
                'protocol': status.version.protocol if status.version else 0,
                'players_online': status.players_online,
                'players_max': status.players_max,
                'latency': round(status.latency, 2),
                'map_name': status.map_name if hasattr(status, 'map_name') else '',
                'gamemode': status.gamemode if hasattr(status, 'gamemode') else '',
            }

            print_found(f"Bedrock Version: {info['version']}")
            print_found(f"Players: {info['players_online']}/{info['players_max']}")
            print_found(f"Latency: {info['latency']}ms")

            return info

        except Exception as e:
            print_fail(f"Bedrock status error: {e}")
            return None

    def _raw_handshake(self) -> Optional[Dict]:
        """Raw TCP Minecraft protocol handshake - extracts maximum info"""
        print_info("Performing raw protocol handshake...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((self.domain, self.port))

            # Build Minecraft handshake packet
            # Protocol version (latest) + server address + port + next state (1=status)
            protocol_version = self._encode_varint(767)  # 1.21.x
            server_addr = self.domain.encode('utf-8')
            server_addr_len = self._encode_varint(len(server_addr))
            server_port = struct.pack('>H', self.port)
            next_state = self._encode_varint(1)

            # Handshake packet (ID 0x00)
            handshake_data = (
                self._encode_varint(0) +  # Packet ID
                protocol_version +
                server_addr_len + server_addr +
                server_port +
                next_state
            )
            handshake_packet = self._encode_varint(len(handshake_data)) + handshake_data

            # Status request packet (ID 0x00, empty)
            status_request = self._encode_varint(1) + self._encode_varint(0)

            sock.send(handshake_packet + status_request)

            # Read response
            raw_response = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    raw_response += chunk
                    if len(raw_response) > 32768:
                        break
                except socket.timeout:
                    break

            sock.close()

            if raw_response:
                # Try to extract JSON from response
                try:
                json_start = raw_response.index(b'{')
                    json_end = raw_response.rindex(b'}') + 1
                    json_str = raw_response[json_start:json_end].decode('utf-8', errors='ignore')
                    data = json.loads(json_str)

                    print_found("Raw handshake successful!")

                    # Check for forwarded-for or real IP in response
                    raw_str = json.dumps(data)
                    ips_found = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_str)
                    if ips_found:
                        print_warn(f"IPs in handshake response: {ips_found}")

                    # Check for BungeeCord/Velocity forwarding info
                    if 'forgeData' in data or 'modinfo' in data:
                        print_found("Forge/Mod data detected in response")

                    return {
                        'success': True,
                        'data': data,
                        'ips_found': ips_found,
                        'raw_size': len(raw_response)
                    }

                except (ValueError, json.JSONDecodeError):
                    print_info(f"Raw response received ({len(raw_response)} bytes) but not JSON")
                    # Check raw bytes for IP patterns
                    raw_text = raw_response.decode('utf-8', errors='ignore')
                    ips_found = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_text)
                    if ips_found:
                        print_warn(f"IPs in raw response: {ips_found}")
                    return {'success': False, 'raw_size': len(raw_response), 'ips_found': ips_found}

        except Exception as e:
            print_fail(f"Raw handshake error: {e}")
            return None

    def _scan_mc_ports(self) -> Dict:
        """Scan common Minecraft-related ports"""
        print_info("Scanning Minecraft-related ports...")
        ports_to_scan = {
            2565: "MC Java Default",
            2566: "MC Java Alt",
            2567: "MC Java Alt 2",
            2575: "RCON",
            19132: "MC Bedrock",
            19133: "MC Bedrock Alt",
            8123: "Dynmap",
            8100: "Dynmap Alt",
            8443: "BlueMap HTTPS",
            8080: "Web Panel",
            8443: "Pterodactyl",
            443: "HTTPS",
            80: "HTTP",
            22: "SSH",
            3306: "MySQL",
            6379: "Redis",
            27017: "MongoDB",
            8192: "GeyserMC",
        }

        open_ports = {}

        def scan_port(port, desc):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.domain, port))
                sock.close()
                if result == 0:
                    return (port, desc, True)
                return (port, desc, False)
            except Exception:
                return (port, desc, False)

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(scan_port, port, desc): port
                for port, desc in ports_to_scan.items()
            }
            for future in concurrent.futures.as_completed(futures):
                port, desc, is_open = future.result()
                if is_open:
                open_ports[port] = desc
                    print_found(f"Port {port} OPEN ({desc})")

        return open_ports

    def _ping_analysis(self) -> Dict:
        """Detailed ping/latency analysis"""
        print_info("Performing ping analysis...")
        results = {'tcp_pings': [], 'icmp_ping': None}

        # TCP ping (multiple samples)
        for i in range(5):
            try:
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(TIMEOUT)
                sock.connect((self.domain, self.port))
                latency = (time.time() - start) * 1000
                sock.close()
                results['tcp_pings'].append(round(latency, 2))
            except Exception:
                results['tcp_pings'].append(None)
            time.sleep(0.2)

        valid_pings = [p for p in results['tcp_pings'] if p is not None]
        if valid_pings:
            avg = sum(valid_pings) / len(valid_pings)
            min_p = min(valid_pings)
            max_p = max(valid_pings)
            jitter = max_p - min_p

            results['avg_latency'] = round(avg, 2)
            results['min_latency'] = round(min_p, 2)
            results['max_latency'] = round(max_p, 2)
            results['jitter'] = round(jitter, 2)

            # Determine status
            if avg < 50:
                status = "EXCELLENT"
            elif avg < 100:
                status = "GOOD"
            elif avg < 200:
                status = "NORMAL"
            elif avg < 500:
                status = "LAG"
            else:
                status = "SEVERE LAG"

            results['status'] = status

            print_found(f"Avg Latency: {avg:.2f}ms")
            print_found(f"Min/Max: {min_p:.2f}ms / {max_p:.2f}ms")
            print_found(f"Jitter: {jitter:.2f}ms")
            print_found(f"Status: {status}")
        else:
            results['status'] = "DOWN/UNREACHABLE"
            print_fail("Server appears DOWN or unreachable")

        # ICMP ping
        try:
            output = subprocess.run(
                ['ping', '-c', '5', '-W', '3', self.domain],
                capture_output=True, text=True, timeout=20
            )
            if output.returncode == 0:
                # Parse ping output
                match = re.search(
                    r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)',
                    output.stdout
                )
                if match:
                    results['icmp_ping'] = {
                        'min': float(match.group(1)),
                        'avg': float(match.group(2)),
                'max': float(match.group(3)),
                        'mdev': float(match.group(4)),
                    }
                    print_found(f"ICMP Ping: {results['icmp_ping']['avg']:.2f}ms avg")
            else:
                print_info("ICMP ping blocked (firewall filtering)")
                results['icmp_blocked'] = True
        except Exception:
            print_info("ICMP ping unavailable")

        return results

    @staticmethod
    def _encode_varint(value: int) -> bytes:
        """Encode integer as Minecraft VarInt"""
        result = b''
        while True:
            byte = value & 0x7F
            value >>= 7
            if value != 0:
                byte |= 0x80
            result += struct.pack('B', byte)
            if value == 0:
                break
        return result


# ================================================================
#     MODULE 5: FIREWALL & PROTECTION DETECTION
# ================================================================

class FirewallDetector:
    """Detect what protection/firewall is in front of the MC server"""

    def __init__(self, domain: str, resolved_ip: str = None):
        self.domain = domain
        self.resolved_ip = resolved_ip or resolve_ip(domain)
        self.protections_found = []

    def run_all(self) -> Dict:
        print_header("MODULE 5: Firewall & Protection Detection")

        results = {}
        results['ip_range_check'] = self._check_ip_ranges()
        results['reverse_dns'] = self._reverse_dns_check()
        results['whois_info'] = self._whois_check()
        results['http_headers'] = self._http_header_check()
        results['ssl_cert'] = self._ssl_certificate_check()
        results['traceroute'] = self._traceroute_analysis()
        results['ttl_analysis'] = self._ttl_analysis()
        results['protections_found'] = self.protections_found

        return results

    def _check_ip_ranges(self) -> Dict:
        """Check if resolved IP belongs to known protection services"""
        print_info(f"Checking IP {self.resolved_ip} against known protection ranges...")

        if not self.resolved_ip:
            print_fail("No IP to check")
            return {}

        detected = {}
        for service, indicators in KNOWN_PROTECTIONS.items():
            for indicator in indicators:
                if self.resolved_ip.startswith(indicator):
                    detected[service] = True
                    self.protections_found.append(service)
                    print_warn(f"DETECTED: {service.upper()} protection (IP prefix: {indicator})")
                    break

        if not detected:
            print_found("IP does not match known protection service ranges")
            print_info("This could be the REAL IP or an unknown protection")

        return detected

    def _reverse_dns_check(self) -> Optional[str]:
        """Reverse DNS lookup on the resolved IP"""
        print_info(f"Reverse DNS lookup for {self.resolved_ip}...")
        if not self.resolved_ip:
            return None

        try:
            rev_name = dns.reversename.from_address(self.resolved_ip)
            answers = dns.resolver.resolve(rev_name, 'PTR')
            for rdata in answers:
                ptr = str(rdata).rstrip('.')
                print_found(f"PTR Record: {ptr}")

                # Check if PTR reveals protection service
                ptr_lower = ptr.lower()
                for service, indicators in KNOWN_PROTECTIONS.items():
                    for indicator in indicators:
                        if indicator in ptr_lower:
                            if service not in self.protections_found:
                self.protections_found.append(service)
                            print_warn(f"PTR reveals: {service.upper()}")

                return ptr
        except Exception as e:
            print_info(f"No PTR record found: {e}")
            return None

    def _whois_check(self) -> Dict:
        """WHOIS lookup to identify hosting/protection provider"""
        print_info(f"WHOIS lookup for {self.resolved_ip}...")
        whois_info = {}

        if not self.resolved_ip:
            return whois_info

        # Using ipwhois library
        if IPWhois:
            try:
                obj = IPWhois(self.resolved_ip)
                result = obj.lookup_rdap(depth=1)
                whois_info = {
                    'asn': result.get('asn', '),
                    'asn_description': result.get('asn_description', ''),
                    'asn_country': result.get('asn_country_code', ''),
                    'network_name': result.get('network', {}).get('name', ''),
                    'network_cidr': result.get('asn_cidr', ''),
                }

                print_found(f"ASN: {whois_info['asn']}")
                print_found(f"ASN Desc: {whois_info['asn_description']}")
                print_found(f"Country: {whois_info['asn_country']}")
                print_found(f"Network: {whois_info['network_name']}")
                print_found(f"CIDR: {whois_info['network_cidr']}")

                # Check ASN description for known services
                asn_desc = whois_info['asn_description'].lower()
                for service in KNOWN_PROTECTIONS:
                    if service in asn_desc:
                        if service not in self.protections_found:
                self.protections_found.append(service)
                        print_warn(f"ASN reveals: {service.upper()}")

            except Exception as e:
                print_fail(f"RDAP lookup error: {e}")

        # Fallback: command line whois
        try:
            output = subprocess.run(
                ['whois', self.resolved_ip],
                capture_output=True, text=True, timeout=15
            )
            if output.returncode == 0:
                whois_text = output.stdout
                # Extract org name
                org_match = re.search(r'(?:OrgName|org-name|descr):\s*(.+)', whois_text, re.I)
                if org_match:
                    org = org_match.group(1).strip()
                    whois_info['org'] = org
                print_found(f"Organization: {org}")

                org_lower = org.lower()
                    for service in KNOWN_PROTECTIONS:
                        if service in org_lower:
                            if service not in self.protections_found:
                                self.protections_found.append(service)
                            print_warn(f"WHOIS reveals: {service.upper()}")
        except Exception:
            pass

        return whois_info

    def _http_header_check(self) -> Dict:
        """Check HTTP headers for protection signatures"""
        print_info("Checking HTTP headers for protection signatures...")
        headers_info = {}

        for port in [80, 443, 8080, 8443, 8123]:
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{self.domain}:{port}"
                    session = get_session()
                    resp = session.get(url, timeout=5, allow_redirects=False, verify=False)

                    headers = dict(resp.headers)
                    headers_info[f"{scheme}:{port}"] = headers

                    # Check for protection signatures
                    server_header = headers.get('Server', ').lower()
                    cf_ray = headers.get('CF-Ray', '')
                    cf_cache = headers.get('CF-Cache-Status', '')
                x_powered = headers.get('X-Powered-By', '')
                    via = headers.get('Via', '')

                    if cf_ray or cf_cache:
                        print_warn(f"Cloudflare detected (CF-Ray: {cf_ray})")
                        if 'cloudflare' not in self.protections_found:
                            self.protections_found.append('cloudflare')

                    if 'tcpshield' in server_header:
                        print_warn("TCPShield detected in Server header")
                        if 'tcpshield' not in self.protections_found:
                            self.protections_found.append('tcpshield')

                    if 'ddos-guard' in server_header:
                print_warn("DDoS-Guard detected")
                        if 'ddos-guard' not in self.protections_found:
                            self.protections_found.append('ddos-guard')

                    print_found(f"{scheme}:{port} → Server: {headers.get('Server', 'N/A')}")

                except Exception:
                    continue

        return headers_info

    def _ssl_certificate_check(self) -> Dict:
        """Extract SSL certificate info - may reveal real hostname/IP"""
        print_info("Analyzing SSL/TLS certificates...")
        cert_info = {}

        targets = [(self.domain, 443), (self.domain, MC_DEFAULT_PORT)]
        if self.resolved_ip:
            targets.append((self.resolved_ip, 443))
            targets.append((self.resolved_ip, MC_DEFAULT_PORT))

        for host, port in targets:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        cert_bin = ssock.getpeercert(binary_form=True)
                        cert_dict = ssock.getpeercert()

                        if cert_dict:
                            subject = dict(x[0] for x in cert_dict.get('subject', []))
                            issuer = dict(x[0] for x in cert_dict.get('issuer', []))
                san = cert_dict.get('subjectAltName', [])

                            cn = subject.get('commonName', '')
                            issuer_cn = issuer.get('commonName', '')

                            print_found(f"SSL [{host}:{port}] CN: {cn}")
                            print_found(f"SSL [{host}:{port}] Issuer: {issuer_cn}")

                            # Check SANs for IP addresses or hostnames
                            for san_type, san_value in san:
                                print_found(f"SSL [{host}:{port}] SAN: {san_type}={san_value}")
                                if san_type == 'IP Address':
                                    print_warn(f"IP in SSL SAN: {san_value}")

                            cert_info[f"{host}:{port}"] = {
                                'cn': cn,
                                'issuer': issuer_cn,
                                'san': san,
                                'not_before': cert_dict.get('notBefore', ''),
                                'not_after': cert_dict.get('notAfter', ''),
                            }

                # Also parse with cryptography library for more detail
                        if x509 and cert_bin:
                            cert_obj = x509.load_der_x509_certificate(
                                cert_bin, default_backend()
                            )
                serial = cert_obj.serial_number
                            fingerprint = cert_obj.fingerprint(
                                cert_obj.signature_hash_algorithm
                            ).hex()
                            print_found(f"SSL Fingerprint: {fingerprint[:40]}...")

            except Exception as e:
                pass  # Many ports won't have SSL

        return cert_info

    def _traceroute_analysis(self) -> List:
        """Traceroute to detect proxy hops"""
        print_info(f"Running traceroute to {self.domain}...")
        hops = []

        try:
            output = subprocess.run(
                ['traceroute', '-n', '-m', '20', '-w', '2', self.domain],
                capture_output=True, text=True, timeout=60
            )
            if output.returncode == 0:
                for line in output.stdout.strip().split('\n')[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        hop_num = parts[0]
                hop_ip = parts[1] if parts[1] != '*' else 'timeout'
                        hops.append({'hop': hop_num, 'ip': hop_ip})
                        if hop_ip != 'timeout':
                            print_found(f"Hop {hop_num}: {hop_ip}")
                else:
                            print_info(f"Hop {hop_num}: * (filtered)")

                # Analyze last few hops for protection detection
                real_hops = [h for h in hops if h['ip'] != 'timeout']
                if len(real_hops) >= 2:
                    last_hop = real_hops[-1]['ip']
                    second_last = real_hops[-2]['ip']
                    if last_hop != self.resolved_ip:
                        print_warn(f"Last hop ({last_hop}) differs from resolved IP ({self.resolved_ip})")
                        print_warn("This may indicate a proxy/protection layer")

        except subprocess.TimeoutExpired:
            print_warn("Traceroute timed out")
        except FileNotFoundError:
            print_fail("traceroute not installed")
        except Exception as e:
            print_fail(f"Traceroute error: {e}")

        return hops

    def _ttl_analysis(self) -> Dict:
        """Analyze TTL values to detect proxy"""
        print_info("Analyzing TTL values...")
        ttl_info = {}

        try:
            output = subprocess.run(
                ['ping', '-c', '3', '-W', '3', self.domain],
                capture_output=True, text=True, timeout=15
            )
            if output.returncode == 0:
                ttls = re.findall(r'ttl=(\d+)', output.stdout)
                if ttls:
                    ttl_values = [int(t) for t in ttls]
                    avg_ttl = sum(ttl_values) / len(ttl_values)
                    ttl_info['values'] = ttl_values
                ttl_info['average'] = avg_ttl

                    # TTL analysis
                    if avg_ttl > 200:
                        ttl_info['os_guess'] = "Likely proxy/CDN (high TTL)"
                        print_warn(f"TTL {avg_ttl:.0f} suggests proxy/CDN")
                    elif avg_ttl > 100:
                        ttl_info['os_guess'] = "Linux/Unix (TTL ~128 or ~64 with hops)"
                    elif avg_ttl > 50:
                        ttl_info['os_guess'] = "Linux (TTL ~64)"
                    else:
                        ttl_info['os_guess'] = "Many hops or filtered"

                    print_found(f"TTL: {ttl_values} → {ttl_info['os_guess']}")

        except Exception:
            pass

        # DNS TTL
        try:
            answers = dns.resolver.resolve(self.domain, 'A')
            dns_ttl = answers.rrset.ttl
            ttl_info['dns_ttl'] = dns_ttl
            print_found(f"DNS TTL: {dns_ttl}s")

            if dns_ttl < 60:
                print_warn("Very low DNS TTL - typical of CDN/proxy services")
            elif dns_ttl < 300:
                print_info("Low DNS TTL - may indicate dynamic DNS or proxy")
            else:
                print_info("Normal DNS TTL")

        except Exception:
            pass

        return ttl_info


# ================================================================
#     MODULE 6: SHODAN & CENSYS OSINT
# ================================================================

class OSINTScanner:
    """Search Shodan, Censys, and other OSINT sources"""

    def __init__(self, domain: str, resolved_ip: str = None):
        self.domain = domain
        self.resolved_ip = resolved_ip or resolve_ip(domain)
        self.found_ips = set()

    def run_all(self) -> Dict:
        print_header("MODULE 6: OSINT Intelligence Gathering")

        results = {}
        results['shodan'] = self._shodan_search()
        results['censys'] = self._censys_search()
        results['fofa'] = self._fofa_search()
        results['internetdb'] = self._internetdb_lookup()
        results['ipinfo'] = self._ipinfo_lookup()

        return {"osint_results": results, "found_ips": list(self.found_ips)}

    def _shodan_search(self) -> Dict:
        """Search Shodan for the domain/IP"""
        print_info("Querying Shodan InternetDB (no API key needed)...")
        results = {}

        if self.resolved_ip:
            try:
                session = get_session()
                resp = session.get(
                    f"https://internetdb.shodan.io/{self.resolved_ip}",
                    timeout=10
                )
                if resp.status_code == 200:
                data = resp.json()
                    results['ports'] = data.get('ports', [])
                    results['hostnames'] = data.get('hostnames', [])
                    results['cpes'] = data.get('cpes', [])
                    results['vulns'] = data.get('vulns', [])
                    results['tags'] = data.get('tags', [])

                    print_found(f"Shodan Ports: {results['ports']}")
                    print_found(f"Shodan Hostnames: {results['hostnames']}")
                    if results['vulns']:
                        print_warn(f"Shodan Vulns: {results['vulns']}")
                    if results['tags']:
                        print_found(f"Shodan Tags: {results['tags']}")

                # Hostnames may reveal real server
                    for hostname in results['hostnames']:
                        try:
                            ip = socket.gethostbyname(hostname)
                            self.found_ips.add(ip)
                            print_found(f"Shodan hostname resolved: {hostname} → {ip}")
                        except socket.gaierror:
                            pass

            except Exception as e:
                print_fail(f"Shodan error: {e}")

        # Also search by domain using Shodan's DNS
        try:
            session = get_session()
            resp = session.get(
                f"https://api.shodan.io/dns/resolve?hostnames={self.domain}&key=",
                timeout=5
            )
        except Exception:
            pass

        return results

    def _censys_search(self) -> Dict:
        """Search Censys for certificates mentioning the domain"""
        print_info("Querying Censys (certificate search)...")
        results = {}

        try:
            session = get_session()
            resp = session.get(
                f"https://search.censys.io/api/v1/search/certificates",
                params={'q': self.domain, 'per_page': 25},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                results['total'] = data.get('metadata', {}).get('count', 0)
                print_found(f"Censys found {results['total']} certificates")
        except Exception as e:
            print_info(f"Censys API requires authentication: {e}")

        return results

    def _fofa_search(self) -> Dict:
        """Search FOFA for the domain"""
        print_info("Querying FOFA...")
        results = {}
        try:
            import base64
            query = base64.b64encode(f'domain="{self.domain}"'.encode()).decode()
            session = get_session()
            resp = session.get(
                f"https://fofa.info/result?qbase64={query}",
                timeout=10
            )
            if resp.status_code == 200:
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp.text)
                unique_ips = set(ips)
                for ip in unique_ips:
                    if not is_private_ip(ip):
                        self.found_ips.add(ip)
                        print_found(f"FOFA IP: {ip}")
                results['ips'] = list(unique_ips)
        except Exception as e:
            print_fail(f"FOFA error: {e}")

        return results

    def _internetdb_lookup(self) -> Dict:
        """Shodan InternetDB for quick port/vuln info"""
        print_info("Checking InternetDB for all discovered IPs...")
        results = {}

        # Check all unique IPs we've found so far
        for ip in list(self.found_ips):
            try:
                session = get_session()
                resp = session.get(f"https://internetdb.shodan.io/{ip}", timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    if 2565 in data.get('ports', []):
                        print_warn(f"InternetDB: {ip} has port 25565 OPEN!")
                        results[ip] = data
            except Exception:
                continue

        return results

    def _ipinfo_lookup(self) -> Dict:
        """IPInfo.io lookup"""
        print_info("Querying IPInfo.io...")
        results = {}

        if self.resolved_ip:
            try:
                session = get_session()
                resp = session.get(
                    f"https://ipinfo.io/{self.resolved_ip}/json",
                    timeout=10
                )
                if resp.status_code == 200:
                    data = resp.json()
                    results = {
                        'ip': data.get('ip', ''),
                        'hostname': data.get('hostname', '),
                        'city': data.get('city', ''),
                        'region': data.get('region', ''),
                        'country': data.get('country', ''),
                        'org': data.get('org', '),
                        'timezone': data.get('timezone', '),
                    }
                    print_found(f"IPInfo: {results['org']} ({results['city']}, {results['country']})")

                # Check if org reveals protection
                    org_lower = results['org'].lower()
                    for service in KNOWN_PROTECTIONS:
                if service in org_lower:
                            print_warn(f"IPInfo confirms: {service.upper()} protection")

            except Exception as e:
                print_fail(f"IPInfo error: {e}")

        return results


# ================================================================
#     MODULE 7: ADVANCED IP DISCOVERY TECHNIQUES
# ================================================================

class AdvancedDiscovery:
    """Advanced techniques to find the real IP behind protection"""

    def __init__(self, domain: str, all_ips: Set[str], protections: List[str]):
        self.domain = domain
        self.all_ips = all_ips
        self.protections = protections
        self.candidate_ips = set()

    def run_all(self) -> Dict:
        print_header("MODULE 7: Advanced Real IP Discovery")

        results = {}
        results['mail_probe'] = self._mail_server_probe()
        results['direct_ip_scan'] = self._direct_ip_mc_probe()
        results['favicon_hash'] = self._favicon_hash_match()
        results['websocket_probe'] = self._websocket_probe()
        results['ipv6_leak'] = self._ipv6_leak_check()

        return {"advanced_results": results, "candidate_ips": list(self.candidate_ips)}

    def _mail_server_probe(self) -> Dict:
        """Connect to mail servers which often share the same IP"""
        print_info("Probing mail servers for IP leaks...")
        results = {}

        try:
            mx_answers = dns.resolver.resolve(self.domain, 'MX')
            for rdata in mx_answers:
                mx_host = str(rdata.exchange).rstrip('.')
                mx_ip = resolve_ip(mx_host)
                if mx_ip:
                    # Try SMTP connection to get banner
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(5)
                        sock.connect((mx_ip, 25))
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        sock.close()

                        print_found(f"SMTP Banner ({mx_ip}): {banner.strip()[:80]}")

                        # Extract IPs from banner
                        banner_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', banner)
                        for ip in banner_ips:
                            self.candidate_ips.add(ip)
                            print_warn(f"IP in SMTP banner: {ip}")

                        results[mx_host] = {
                            'ip': mx_ip, 'banner': banner.strip()[:200]
                        }
                    except Exception:
                        pass

                # Also try port 587 (submission)
                    try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                        sock.connect((mx_ip, 587))
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        sock.close()
                        print_found(f"SMTP Submission Banner ({mx_ip}:587): {banner.strip()[:80]}")
                    except Exception:
                        pass

        except Exception as e:
            print_fail(f"MX probe error: {e}")

        return results

    def _direct_ip_mc_probe(self) -> Dict:
        """Try connecting to candidate IPs directly on MC port"""
        print_info("Probing candidate IPs for Minecraft service...")
        results = {}

        # Collect all candidate IPs
        all_candidates = set(self.all_ips) | self.candidate_ips

        for ip in all_candidates:
            if is_private_ip(ip):
                continue

            for port in [2565, 25566, 2567]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((ip, port))

                    # Try MC handshake
                    protocol_version = MinecraftProbe._encode_varint(767)
                    server_addr = ip.encode('utf-8')
                    server_addr_len = MinecraftProbe._encode_varint(len(server_addr))
                    server_port = struct.pack('>H', port)
                    next_state = MinecraftProbe._encode_varint(1)

                    handshake_data = (
                        MinecraftProbe._encode_varint(0) +
                        protocol_version +
                        server_addr_len + server_addr +
                        server_port +
                        next_state
                )
                    handshake_packet = (
                        MinecraftProbe._encode_varint(len(handshake_data)) + handshake_data
                    )
                    status_request = MinecraftProbe._encode_varint(1) + MinecraftProbe._encode_varint(0)

                    sock.send(handshake_packet + status_request)

                    response = b''
                    try:
                        while True:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                            if len(response) > 16384:
                                break
                    except socket.timeout:
                        pass

                    sock.close()

                    if response and b'{' in response:
                        try:
                            json_start = response.index(b'{')
                            json_end = response.rindex(b'}') + 1
                            json_str = response[json_start:json_end].decode('utf-8', errors='ignore')
                            data = json.loads(json_str)

                            version = data.get('version', {}).get('name', 'Unknown')
                            players = data.get('players', {})
                            desc = data.get('description', '')

                            if isinstance(desc, dict):
                                desc = desc.get('text', str(desc))

                            print_warn(f"MC SERVER FOUND: {ip}:{port}")
                            print_result("  Version", version)
                            print_result("  Players", f"{players.get('online', '?')}/{players.get('max', '?')}")
                            print_result("  MOTD", str(desc)[:80])

                            self.candidate_ips.add(ip)
                            results[f"{ip}:{port}"] = {
                                'version': version,
                                'players': players,
                                'motd': str(desc)[:200],
                                'is_minecraft': True
                            }

                        except (ValueError, json.JSONDecodeError):
                print_found(f"TCP response from {ip}:{port} (not JSON)")
                            results[f"{ip}:{port}"] = {'is_minecraft': False, 'has_response': True}

                except Exception:
                    continue

        return results

    def _favicon_hash_match(self) -> Dict:
        """Compare server favicons to match real IP"""
        print_info("Comparing server favicons across IPs...")
        results = {}

        # Get favicon from domain first
        domain_favicon = None
        try:
            server = JavaServer.lookup(f"{self.domain}:{MC_DEFAULT_PORT}")
            status = server.status()
            if hasattr(status, 'favicon') and status.favicon:
                domain_favicon = hashlib.md5(status.favicon.encode()).hexdigest()
                print_found(f"Domain favicon hash: {domain_favicon}")
                results['domain_favicon_hash'] = domain_favicon
        except Exception:
            print_info("Could not get domain favicon")

        return results

    def _websocket_probe(self) -> Dict:
        """Check for WebSocket connections that may leak IP"""
        print_info("Checking for WebSocket/map services...")
        results = {}

        # Common map plugins expose WebSocket
        map_paths = [
            '/up/world/world/',  # Dynmap
            '/tiles/',           # BlueMap
            '/api/v1/',          # Various
        ]

        for port in [8123, 8100, 8443, 80, 443]:
            for path in map_paths:
                try:
                    url = f"http:/{self.domain}:{port}{path}"
                    session = get_session()
                    resp = session.get(url, timeout=3, allow_redirects=True)
                    if resp.status_code == 200:
                        print_found(f"Map service found: {url}")

                        # Check response for IP leaks
                        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp.text)
                        for ip in set(ips):
                            if not is_private_ip(ip):
                                self.candidate_ips.add(ip)
                                print_warn(f"IP in map response: {ip}")

                        results[url] = {'status': resp.status_code}
                except Exception:
                    continue

        return results

    def _ipv6_leak_check(self) -> Dict:
        """Check if IPv6 leaks the real server"""
        print_info("Checking for IPv6 leaks...")
        results = {}

        try:
            answers = dns.resolver.resolve(self.domain, 'AA')
            for rdata in answers:
                ipv6 = str(rdata)
                print_found(f"IPv6: {ipv6}")
                results['ipv6'] = ipv6

                # Try to connect via IPv6
                try:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((ipv6, MC_DEFAULT_PORT))
                    print_warn(f"IPv6 MC connection successful! May be real server.")
                    sock.close()
                    results['ipv6_mc_open'] = True
                except Exception:
                    results['ipv6_mc_open'] = False

        except Exception:
            print_info("No IPv6 records found")

        return results


# ================================================================
#                MAIN ANALYSIS ENGINE
# ================================================================

class MCReconEngine:
    """Main orchestrator for all reconnaissance modules"""

    def __init__(self, domain: str, port: int = MC_DEFAULT_PORT):
        self.domain = domain.lower().strip()
        self.port = port
        self.all_ips = set()
        self.protections = []
        self.results = {}
        self.start_time = None

    def run(self):
        self.start_time = time.time()
        print(BANNER)
        print(f"{C}  Target: {W}{self.domain}:{self.port}")
        print(f"{C}  Time:   {W}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{C}  {'═' * 60}{RST}\n")

        # Resolve initial IP
        resolved_ip = resolve_ip(self.domain)
        if resolved_ip:
            self.all_ips.add(resolved_ip)
            print_found(f"Initial Resolution: {self.domain} → {resolved_ip}")
        else:
            print_fail(f"Cannot resolve {self.domain}")
            print_warn("Continuing with other methods...")

        # === MODULE 1: DNS Enumeration ===
        dns_enum = DNSEnumerator(self.domain)
        dns_results = dns_enum.run_all()
        self.all_ips.update(dns_results.get('all_ips', []))
        self.results['dns'] = dns_results

        # === MODULE 2: Subdomain Enumeration ===
        sub_enum = SubdomainEnumerator(self.domain)
        sub_results = sub_enum.run_all()
        self.all_ips.update(sub_results.get('all_ips', []))
        self.results['subdomains'] = sub_results

        # === MODULE 3: Historical DNS ===
        hist_dns = HistoricalDNS(self.domain)
        hist_results = hist_dns.run_all()
        self.all_ips.update(hist_results.get('historical_ips', []))
        self.results['historical'] = hist_results

        # === MODULE 4: Minecraft Protocol Probe ===
        mc_probe = MinecraftProbe(self.domain, self.port)
        mc_results = mc_probe.run_all()
        self.results['minecraft'] = mc_results

        # === MODULE 5: Firewall Detection ===
        fw_detect = FirewallDetector(self.domain, resolved_ip)
        fw_results = fw_detect.run_all()
        self.protections = fw_results.get('protections_found', [])
        self.results['firewall'] = fw_results

        # === MODULE 6: OSINT ===
        osint = OSINTScanner(self.domain, resolved_ip)
        osint_results = osint.run_all()
        self.all_ips.update(osint_results.get('found_ips', []))
        self.results['osint'] = osint_results

        # === MODULE 7: Advanced Discovery ===
        adv = AdvancedDiscovery(self.domain, self.all_ips, self.protections)
        adv_results = adv.run_all()
        self.all_ips.update(adv_results.get('candidate_ips', []))
        self.results['advanced'] = adv_results

        # === FINAL ANALYSIS ===
        self._final_analysis()

    def _final_analysis(self):
        elapsed = time.time() - self.start_time

        print(f"\n\n{C}{'═' * 70}")
        print(f"{'═' * 70}")
        print(f"  {Y}████ FINAL ANALYSIS REPORT ████")
        print(f"{C}{'═' * 70}{RST}\n")

        # 1. All discovered IPs
        print(f"  {M}╔══ ALL DISCOVERED IPs ══╗{RST}")
        resolved_ip = resolve_ip(self.domain)

        # Categorize IPs
        proxy_ips = set()
        candidate_real_ips = set()
        historical_ips = set(self.results.get('historical', {}).get('historical_ips', []))

        for ip in self.all_ips:
            if is_private_ip(ip):
                continue
            is_proxy = False
            for service, indicators in KNOWN_PROTECTIONS.items():
                for indicator in indicators:
                    if ip.startswith(indicator):
                        is_proxy = True
                        proxy_ips.add(ip)
                        break
                if is_proxy:
                break
            if not is_proxy:
                candidate_real_ips.add(ip)

        print(f"\n  {W}Proxy/Protection IPs:{RST}")
        for ip in proxy_ips:
            print(f"    {R}🛡  {ip}{RST}")

        print(f"\n  {W}Candidate Real IPs:{RST}")
        for ip in candidate_real_ips:
            markers = []
            if ip in historical_ips:
                markers.append("HISTORICAL")
            if ip == resolved_ip:
                markers.append("CURRENT")
            marker_str = f" [{', '.join(markers)}]" if markers else ""
            print(f"    {G}🎯 {ip}{Y}{marker_str}{RST}")

        print(f"\n  {W}Historical IPs:{RST}")
        for ip in historical_ips:
            status = "CANDIDATE" if ip in candidate_real_ips else "OLD"
            print(f"    {B}📜 {ip} [{status}]{RST}")

        # 2. Protection Summary
        print(f"\n  {M}╔══ PROTECTION DETECTED ══╗{RST}")
        if self.protections:
            for prot in set(self.protections):
                print(f"    {R}🔒 {prot.upper()}{RST}")
        else:
            print(f"    {G}✓ No known protection detected{RST}")

        # 3. Server Status
        print(f"\n  {M}╔══ SERVER STATUS ══╗{RST}")
        mc_data = self.results.get('minecraft', {})
        java_status = mc_data.get('java_status')
        ping_data = mc_data.get('ping_analysis', {})

        if java_status:
            status_str = ping_data.get('status', 'UNKNOWN')
            color = G if status_str in ['EXCELLENT', 'GOOD', 'NORMAL'] else (Y if status_str == 'LAG' else R)
            print(f"    {color}⚡ Status: {status_str}{RST}")
            print(f"    {W}📊 Version: {java_status.get('version', 'N/A')}{RST}")
            print(f"    {W}👥 Players: {java_status.get('players_online', 0)}/{java_status.get('players_max', 0)}{RST}")
            print(f"    {W}📡 Latency: {java_status.get('latency', 'N/A')}ms{RST}")
        else:
            print(f"    {R}⚠  Server appears DOWN or unreachable{RST}")

        # 4. Best guess for real IP
        print(f"\n  {M}╔══ REAL IP ASSESSMENT ══╗{RST}")
        if candidate_real_ips:
            # Score each candidate
            scored = {}
            for ip in candidate_real_ips:
                score = 0
                reasons = []

                if ip in historical_ips:
                    score += 30
                    reasons.append("Found in historical DNS")

                # Check if MC port is open on this IP
                adv_results = self.results.get('advanced', {}).get('advanced_results', {})
                direct_scan = adv_results.get('direct_ip_scan', {})
                for key, val in direct_scan.items():
                    if ip in key and val.get('is_minecraft'):
                        score += 50
                        reasons.append("Minecraft server confirmed on this IP")

                # Check subdomains pointing to this IP
                sub_data = self.results.get('subdomains', {}).get('subdomains', {})
                sub_count = sum(1 for v in sub_data.values() if v == ip)
                if sub_count > 0:
                    score += sub_count * 10
                    reasons.append(f"{sub_count} subdomain(s) point to this IP")

                # Not a known proxy
                score += 20
                reasons.append("Not in known proxy IP ranges")

                scored[ip] = {'score': score, 'reasons': reasons}

            # Sort by score
            sorted_candidates = sorted(scored.items(), key=lambda x: x[1]['score'], reverse=True)

            for ip, info in sorted_candidates:
                confidence = min(info['score'], 100)
                bar = '█' * (confidence // 5) + '░' * (20 - confidence // 5)
                print(f"\n    {G}🎯 {ip}{RST}")
                print(f"       Confidence: [{bar}] {confidence}%")
                for reason in info['reasons']:
                print(f"       → {reason}")

            best_ip = sorted_candidates[0][0]
            best_score = sorted_candidates[0][1]['score']
            print(f"\n    {G}{'━' * 50}")
            print(f"    ★ MOST LIKELY REAL IP: {best_ip}")
            print(f"    ★ CONFIDENCE: {min(best_score, 100)}%")
            print(f"    {'━' * 50}{RST}")

        else:
            print(f"    {Y}⚠  Could not determine real IP with high confidence{RST}")
            print(f"    {W}   The server may be well-protected or using dedicated proxy{RST}")
            print(f"    {W}   Try: manual Shodan/Censys search with API keys{RST}")

        # 5. Open Ports
        print(f"\n  {M}╔══ OPEN PORTS ══╗{RST}")
        open_ports = mc_data.get('port_scan', {})
        if open_ports:
            for port, desc in open_ports.items():
                print(f"    {G}🔓 {port}/tcp - {desc}{RST}")
        else:
            print(f"    {Y}No open ports detected (heavily filtered){RST}")

        # Footer
        print(f"\n{C}{'═' * 70}")
        print(f"  Scan completed in {elapsed:.2f} seconds")
        print(f"  Total unique IPs discovered: {len(self.all_ips)}")
        print(f"  Candidate real IPs: {len(candidate_real_ips)}")
        print(f"{'═' * 70}{RST}\n")

        # Save results to JSON
        self._save_results()

    def _save_results(self):
        """Save all results to JSON file"""
        filename = f"mc_recon_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            # Convert sets to lists for JSON serialization
            serializable = {
                'target': self.domain,
                'port': self.port,
                'scan_time': datetime.now().isoformat(),
                'all_ips': list(self.all_ips),
                'protections': self.protections,
            }
            with open(filename, 'w') as f:
                json.dump(serializable, f, indent=2, default=str)
            print_found(f"Results saved to: {filename}")
        except Exception as e:
            print_fail(f"Could not save results: {e}")


# ================================================================
#                    INTERACTIVE MENU
# ================================================================

def interactive_menu():
    """Arrow-key style interactive menu"""
    print(BANNER)

    while True:
        print(f"\n{C}╔══════════════════════════╗")
        print(f"║{W}        SELECT OPERATION MODE              {C}║")
        print(f"╠══════════════════════════╣")
        print(f"║                ║")
        print(f"║  {G}[1]{W} 🔍 Cek IP Asli dari Domain          {C}║")
        print(f"║  {G}[2]{W} 📡 Cek Ping/Status Server            {C}║")
        print(f"║  {G}[3]{W} 🛡  Cek Firewall & Proteksi          {C}║")
        print(f"║  {G}[4]{W} 🚀 FULL SCAN (Semua Module)          {C}║")
        print(f"║  {G}[5]{W} 📋 Scan Custom Port                  {C}║")
        print(f"║  {R}[0]{W} ❌ Exit                               {C}║")
        print(f"║                                          ║")
        print(f"╚══════════════════════════╝{RST}")

        choice = input(f"\n  {Y}▶ Pilih [{G}0-5{Y}]: {RST}").strip()

        if choice == '0':
            print(f"\n{G}  Goodbye! 👋{RST}\n")
            sys.exit(0)

        domain = input(f"  {C}▶ Masukkan domain/IP server: {RST}").strip()
        if not domain:
            print_fail("Domain tidak boleh kosong!")
            continue

        # Remove protocol prefix if present
        domain = domain.replace('https://', '').replace('http:/', '')
        domain = domain.split('/')[0]

        # Extract port if provided
        port = MC_DEFAULT_PORT
        if ':' in domain:
            parts = domain.rsplit(':', 1)
            domain = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = MC_DEFAULT_PORT

        if choice == '1':
            # Quick IP detection
            print_header(f"Quick IP Detection: {domain}")
            resolved = resolve_ip(domain)
            if resolved:
                print_found(f"Resolved IP: {resolved}")

            dns_enum = DNSEnumerator(domain)
            dns_enum.run_all()

            sub_enum = SubdomainEnumerator(domain)
            sub_enum.run_all()

            hist = HistoricalDNS(domain)
            hist.run_all()

        elif choice == '2':
            # Ping/Status check
            print_header(f"Server Status Check: {domain}:{port}")
            probe = MinecraftProbe(domain, port)
            probe._java_server_status()
            probe._bedrock_server_status()
            probe._ping_analysis()

        elif choice == '3':
            # Firewall detection
            print_header(f"Firewall Detection: {domain}")
            resolved = resolve_ip(domain)
            fw = FirewallDetector(domain, resolved)
            fw.run_all()

        elif choice == '4':
            # Full scan
            engine = MCReconEngine(domain, port)
            engine.run()

        elif choice == '5':
            # Custom port scan
            custom_port = input(f"  {C}▶ Port (default 25565): {RST}").strip()
            if custom_port:
                try:
                    port = int(custom_port)
                except ValueError:
                    port = MC_DEFAULT_PORT
            engine = MCReconEngine(domain, port)
            engine.run()

        else:
            print_fail("Pilihan tidak valid!")

        input(f"\n  {Y}Press Enter to continue...{RST}")


# ================================================================
#                         ENTRY POINT
# ================================================================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Minecraft Server Real IP Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 mc_recon.py                # Interactive menu
  python3 mc_recon.py -d play.example.com      # Full scan
  python3 mc_recon.py -d example.com -p 25566  # Custom port
  python3 mc_recon.py -d example.com --quick    # Quick scan only
        """
    )
    parser.add_argument('-d', '--domain', help='Target domain')
    parser.add_argument('-p', '--port', type=int, default=2565, help='MC port (default: 25565)')
    parser.add_argument('--quick', action='store_true', help='Quick scan (DNS + subdomain only)')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive menu mode')

    args = parser.parse_args()

    if args.interactive or not args.domain:
        interactive_menu()
    elif args.domain:
        if args.quick:
            print(BANNER)
            print_header(f"Quick Scan: {args.domain}")
            dns_enum = DNSEnumerator(args.domain)
            dns_enum.run_all()
            sub_enum = SubdomainEnumerator(args.domain)
            sub_enum.run_all()
            hist = HistoricalDNS(args.domain)
            hist.run_all()
        else:
            engine = MCReconEngine(args.domain, args.port)
            engine.run()
