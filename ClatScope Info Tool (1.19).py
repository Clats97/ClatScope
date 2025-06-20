import http.client
import textwrap
import urllib.parse
from urllib.parse import quote
import requests 
from pystyle import Colors, Write
from phonenumbers import geocoder, carrier
import phonenumbers
import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
from dns import reversename
from email_validator import validate_email, EmailNotValidError
from urllib.parse import quote
import json
from bs4 import BeautifulSoup
import re
from email.parser import Parser
import whois
from tqdm import tqdm
from datetime import datetime
import magic
import stat
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import PyPDF2
import openpyxl
import docx
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from pptx import Presentation
from mutagen.easyid3 import EasyID3
from mutagen.mp3 import MP3
from mutagen.mp4 import MP4
from mutagen.id3 import ID3
from mutagen.flac import FLAC
import wave
from mutagen.oggvorbis import OggVorbis
from tinytag import TinyTag

default_color = Colors.red
HIBP_API_KEY = "INSERT API KEY HERE"

_global_session = requests.Session()
default_color = Colors.light_red
requests.get = _global_session.get

import multiprocessing
MAX_WORKERS = min(32, (multiprocessing.cpu_count() or 1) * 5)

def bootstrap_deps() -> None:
    import importlib
    import subprocess
    import sys
    required: dict[str, str] = {
        "requests":               "requests",
        "urllib3":                "urllib3",
        "pystyle":                "pystyle",
        "tqdm":                   "tqdm",
        "phonenumbers":           "phonenumbers",
        "dns":                    "dnspython",
        "email_validator":        "email_validator",
        "bs4":                    "beautifulsoup4",
        "whois":                  "python-whois",
        "magic":                  "python-magic-bin;platform_system=='Windows' or platform_system=='Darwin'",
        "python_magic":           "python-magic;platform_system!='Windows' and platform_system!='Darwin'",  
        "PIL":                    "Pillow",
        "PyPDF2":                 "PyPDF2",
        "openpyxl":               "openpyxl",
        "docx":                   "python-docx",
        "pptx":                   "python-pptx",
        "mutagen":                "mutagen",
        "tinytag":                "tinytag",
        "argon2":                 "argon2-cffi",
        "passlib":                "passlib",
    }

    for module_name, pip_spec in required.items():
        try:
            importlib.import_module(module_name)
        except ImportError:
            print(f"[+] Installing missing dependency '{pip_spec}' …", file=sys.stderr, flush=True)
            subprocess.check_call([sys.executable, "-m", "pip", "install", pip_spec])
        finally:
            globals()[module_name.split('.')[0]] = importlib.import_module(module_name)

def validate_domain_input(domain):
    if not domain or len(domain) > 253 or ".." in domain:
        return False
    pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))

def log_option(output_text):
    print()
    print("[?] Would you like to save this output to a log file? (Y/N): ", end="")
    choice = input().strip().upper()
    if choice == 'Y':
        stamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
        with open("clatscope_log.txt", "a", encoding="utf-8") as log_file:
            log_file.write(f"{stamp}{output_text}\n\n")
        Write.Print("[!] > Output has been saved to clatscope_log.txt\n", default_color, interval=0)

def export_json(data, filename_prefix="output"):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_prefix}_{stamp}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        Write.Print(f"[!] > JSON Export complete: {filename}\n", Colors.green, interval=0)
    except Exception as e:
        Write.Print(f"[!] > Failed to write JSON file: {str(e)}\n", Colors.red, interval=0)

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def restart():
    Write.Input("\nPress Enter to return to the main menu...", default_color, interval=0)
    clear()

def get_ip_details(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=60)
        response.raise_for_status()
        return response.json()
    except:
        return None

def ip_info(ip):
    url = f"https://ipinfo.io/{ip}/json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        loc = data.get('loc', 'None')
        maps_link = f"https://www.google.com/maps?q={loc}" if loc != 'None' else 'None'
        ip_details = f"""
╭─{' '*78}─╮
|{' '*34} IP Details {' '*34}|
|{'='*80}|
| [+] > IP Address         || {data.get('ip', 'None'):<51}|
| [+] > City               || {data.get('city', 'None'):<51}|
| [+] > Region             || {data.get('region', 'None'):<51}|
| [+] > Country            || {data.get('country', 'None'):<51}|
| [+] > Postal/ZIP Code    || {data.get('postal', 'None'):<51}|
| [+] > ISP                || {data.get('org', 'None'):<51}|
| [+] > Coordinates        || {loc:<51}|
| [+] > Timezone           || {data.get('timezone', 'None'):<51}|
| [+] > Location           || {maps_link:<51}|
╰─{' '*24}─╯╰─{' '*50}─╯
"""
        Write.Print(ip_details, Colors.white, interval=0)
        log_option(ip_details)

        print("[?] Export IP details in JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json(data, filename_prefix="ip_info")

    except:
        clear()
        Write.Print("\n[!] > Error retrieving IP address info.", default_color, interval=0)
    restart()

def subdomain_enumeration(domain):
    import requests
    from datetime import datetime
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    Write.Print(f"\n[!] Subdomain enumeration for: {domain}\n", Colors.white, interval=0)
    try:
        resp = requests.get(url, timeout=60)
        if resp.status_code == 200:
            try:
                data = resp.json()
            except json.JSONDecodeError:
                msg = "[!] > Error: crt.sh returned non-JSON or empty data.\n"
                Write.Print(msg, Colors.red, interval=0)
                return
            found_subs = set()
            for entry in data:
                if 'name_value' in entry:
                    for subd in entry['name_value'].split('\n'):
                        subd_strip = subd.strip()
                        if subd_strip and subd_strip != domain:
                            found_subs.add(subd_strip)
                elif 'common_name' in entry:
                    c = entry['common_name'].strip()
                    if c and c != domain:
                        found_subs.add(c)
            if found_subs:
                out_text = f"\n[+] Found {len(found_subs)} subdomains for {domain}:\n"
                for s in sorted(found_subs):
                    out_text += f"    {s}\n"
                Write.Print(out_text, Colors.green, interval=0)
                print()
                print("[?] Would you like to save this output to a log file? (Y/N): ", end="")
                choice = input().strip().upper()
                if choice == 'Y':
                    stamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
                    with open("clatscope_log.txt", "a", encoding="utf-8") as f:
                        f.write(stamp + out_text + "\n")
                    Write.Print("[!] > Subdomains saved to clatscope_log.txt\n", Colors.white, interval=0)

                print("[?] Export subdomains as JSON? (Y/N): ", end="")
                if input().strip().upper() == "Y":
                    export_json(list(found_subs), filename_prefix="subdomains")

            else:
                Write.Print("[!] > No subdomains found.\n", Colors.red, interval=0)
        else:
            err = f"[!] > HTTP {resp.status_code} from crt.sh\n"
            Write.Print(err, Colors.red, interval=0)
    except Exception as exc:
        Write.Print(f"[!] > Subdomain enumeration error: {exc}\n", Colors.red, interval=0)

def person_search(first_name: str, last_name: str, city: str) -> str:
    query = f"{first_name} {last_name} {city}".strip()

    payload_person_search = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "Create a well-sourced profile of the target individual.\n\n"
                    "Include:\n"
                    "• Full name and known aliases\n"
                    "• Date/place of birth (or death) and current residence\n"
                    "• Education and career timeline\n"
                    "• Public offices, major events, controversies\n"
                    "• Close family relations\n"
                    "• Publicly available contact details (phone, email, address) only\n"
                    "• Latest verified activities\n\n"
                    "Cite each fact with [Source #] and supply a Chicago-style bibliography. "
                    "Prioritise primary documents, official records, reputable media, or "
                    "peer-reviewed sources; avoid speculation. "
                    "Start by disambiguating anyone else with the same name, then lock onto the "
                    "correct person (occupation, era, location). "
                    "Flag any data that is missing or unverified."
                ),
            },
            {"role": "user", "content": f"Provide the profile for: {query}"},
        ],
        "max_tokens": 8_000,
        "temperature": 0.7,
        "stream": True,
    }

    results_text = ""
    try:
        with requests.post(
            PERPLEXITY_API_URL,
            headers=perplexity_headers,
            json=payload_person_search,
            stream=True,
            timeout=60,  
        ) as response:
            if response.status_code != 200:
                err = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
                print(err)
                return err
            print(
                f"\nPERSON SEARCH RESULTS\n"
                f"=====================\n\n"
                f"NAME:\n{first_name} {last_name}\n\n"
                f"LOCATION:\n{city}\n\n"
                f"PUBLIC INFORMATION:\n",
                end="",
            )
            for raw in response.iter_lines():
                if not raw:
                    continue
                try:
                    line = raw.decode("utf-8").strip()
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:].strip()
                    if data_str == "[DONE]":
                        break
                    chunk = json.loads(data_str)
                    content = chunk["choices"][0].get("delta", {}).get("content", "")
                    if content:
                        print(content, end="", flush=True)
                        results_text += content
                except Exception as chunk_err:
                    msg = f"\n[!] Error processing stream chunk: {chunk_err}"
                    print(msg)
                    results_text += msg

    except requests.exceptions.RequestException as net_err:
        results_text = f"[!] > Network/HTTP error: {net_err}\n"
        print(results_text)
    except Exception as e:
        results_text = f"[!] > Unexpected error: {e}\n"
        print(results_text)
    print("\n")
    clear()
    Write.Print(results_text, Colors.white, interval=0)
    log_option(results_text)
    print("[?] Export person search as JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"search_query": query, "results": results_text}, filename_prefix="person_search")

    restart()
    return results_text

def deep_account_search(nickname):
    sites = [
        "https://youtube.com/@{target}",
        "https://facebook.com/{target}",
        "https://wikipedia.org/wiki/User:{target}",
        "https://instagram.com/{target}",
        "https://reddit.com/user/{target}",
        "https://medium.com/@{target}",
        "https://www.quora.com/profile/{target}",
        "https://bing.com/{target}",
        "https://x.com/{target}",
        "https://yandex.ru/{target}",
        "https://whatsapp.com/{target}",
        "https://yahoo.com/{target}",
        "https://amazon.com/{target}",
        "https://duckduckgo.com/{target}",
        "https://yahoo.co.jp/{target}",
        "https://tiktok.com/@{target}",
        "https://msn.com/{target}",
        "https://netflix.com/{target}",
        "https://weather.com/{target}",
        "https://live.com/{target}",
        "https://naver.com/{target}",
        "https://microsoft.com/{target}",
        "https://twitch.tv/{target}",
        "https://office.com/{target}",
        "https://vk.com/{target}",
        "https://pinterest.com/{target}",
        "https://discord.com/{target}",
        "https://aliexpress.com/{target}",
        "https://github.com/{target}",
        "https://adobe.com/{target}",
        "https://rakuten.co.jp/{target}",
        "https://ikea.com/{target}",
        "https://bbc.co.uk/{target}",
        "https://amazon.co.jp/{target}",
        "https://speedtest.net/{target}",
        "https://samsung.com/{target}",
        "https://healthline.com/{target}",
        "https://medlineplus.gov/{target}",
        "https://roblox.com/users/{target}/profile",
        "https://cookpad.com/{target}",
        "https://indiatimes.com/{target}",
        "https://mercadolivre.com.br/{target}",
        "https://britannica.com/{target}",
        "https://merriam-webster.com/{target}",
        "https://hurriyet.com.tr/{target}",
        "https://steamcommunity.com/user/{target}",
        "https://booking.com/{target}",
        "https://support.google.com/{target}",
        "https://bbc.com/{target}",
        "https://playstation.com/{target}",
        "https://ebay.com/usr/{target}",
        "https://poki.com/{target}",
        "https://walmart.com/{target}",
        "https://medicalnewstoday.com/{target}",
        "https://gov.uk/{target}",
        "https://nhs.uk/{target}",
        "https://detik.com/{target}",
        "https://cricbuzz.com/{target}",
        "https://nih.gov/{target}",
        "https://uol.com.br/{target}",
        "https://ilovepdf.com/{target}",
        "https://clevelandclinic.org/{target}",
        "https://cnn.com/{target}",
        "https://globo.com/{target}",
        "https://nytimes.com/{target}",
        "https://taboola.com/{target}",
        "https://pornhub.com/users/{target}",
        "https://redtube.com/users/{target}",
        "https://xnxx.com/profiles/{target}",
        "https://brazzers.com/profile/{target}",
        "https://xhamster.com/users/{target}",
        "https://onlyfans.com/{target}",
        "https://xvideos.es/profiles/{target}",
        "https://xvideos.com/profiles/{target}",
        "https://chaturbate.com/{target}",
        "https://redgifs.com/users/{target}",
        "https://tinder.com/{target}",
        "https://pof.com/{target}",
        "https://match.com/{target}",
        "https://eharmony.com/{target}",
        "https://bumble.com/{target}",
        "https://okcupid.com/{target}",
        "https://Badoo.com/{target}",
        "https://dating.com/{target}",
        "https://trello.com/{target}",
        "https://mapquest.com/{target}",
        "https://zoom.com/{target}",
        "https://apple.com/{target}",
        "https://dropbox.com/{target}",
        "https://weibo.com/{target}",
        "https://wordpress.com/{target}",
        "https://cloudflare.com/{target}",
        "https://salesforce.com/{target}",
        "https://fandom.com/{target}",
        "https://paypal.com/{target}",
        "https://soundcloud.com/{target}",
        "https://forbes.com/{target}",
        "https://theguardian.com/{target}",
        "https://hulu.com/{target}",
        "https://stackoverflow.com/users/{target}",
        "https://businessinsider.com/{target}",
        "https://huffpost.com/{target}",
        "https://booking.com/{target}",
        "https://pastebin.com/u/{target}",
        "https://producthunt.com/@{target}",
        "https://pypi.org/user/{target}",
        "https://slideshare.com/{target}",
        "https://strava.com/athletes/{target}",
        "https://tldrlegal.com/{target}",
        "https://t.me/{target}",
        "https://last.fm/user{target}",
        "https://data.typeracer.com/pit/profile?user={target}",
        "https://tryhackme.com/p/{target}",
        "https://trakt.tv/users/{target}",
        "https://scratch.mit.edu/users/{target}",
        "https://replit.com?{target}",
        "https://hackaday.io/{target}",
        "https://freesound.org/people/{target}",
        "https://hub.docker.com/u/{target}",
        "https://disqus.com/{target}",
        "https://www.codecademy.com/profiles/{target}",
        "https://www.chess.com/member/{target}",
        "https://bitbucket.org/{target}",
        "https://www.twitch.tv?{target}",
        "https://wikia.com/wiki/User:{target}",
        "https://steamcommunity.com/groups{target}",
        "https://keybase.io?{target}",
        "http://en.gravatar.com/{target}",
        "https://vk.com/{target}",
        "https://deviantart.com/{target}",
        "https://www.behance.net/{target}",
        "https://vimeo.com/{target}",
        "https://www.youporn.com/user/{target}",
        "https://profiles.wordpress.org/{target}",
        "https://tryhackme.com/p/{target}",
        "https://www.scribd.com/{target}",
        "https://myspace.com/{target}",
        "https://genius.com/{target}",
        "https://genius.com/artists/{target}",
        "https://www.flickr.com/people/{target}",
        "https://www.fandom.com/u/{target}",
        "https://www.chess.com/member/{target}",
        "https://buzzfeed.com/{target}",
        "https://www.buymeacoffee.com/{target}",
        "https://about.me/{target}",
        "https://discussions.apple.com/profile/{target}",
        "https://giphy.com/{target}",
        "https://scholar.harvard.edu/{target}",
        "https://www.instructables.com/member/{target}",
        "http://www.wikidot.com/user:info/{target}",
        "https://erome.com/{target}",
        "https://www.alik.cz/u/{target}",
        "https://rblx.trade/p/{target}",
        "https://www.paypal.com/paypalme/{target}",
        "https://hackaday.io/{target}",
        "https://connect.garmin.com/modern/profile/{target}"
    ]
    urls = [site_format.format(target=nickname) for site_format in sites]

    def check_url(url):
        try:
            response = requests.get(url, timeout=60)
            status_code = response.status_code
            if status_code == 200:
                return f"[+] > {url:<50}|| Found"
            elif status_code == 404:
                return f"[-] > {url:<50}|| Not found"
            else:
                return f"[-] > {url:<50}|| Error: {status_code}"
        except requests.exceptions.Timeout:
            return f"[-] > {url:<50}|| Timeout"
        except requests.exceptions.ConnectionError:
            return f"[-] > {url:<50}|| Connection error"
        except requests.exceptions.RequestException:
            return f"[-] > {url:<50}|| Request error"
        except Exception:
            return f"[-] > {url:<50}|| Unexpected error"

    title = "Deep Account Search"
    def fetch_social_urls(urls, title):
        result_str = f"""
╭─{' '*78}─╮
|{' '*27}{title}{' '*27}|
|{'='*80}|
"""
        with ThreadPoolExecutor() as executor:
            executor._max_workers = MAX_WORKERS
            results = list(executor.map(check_url, urls))
        for result in results:
            result_str += f"| {result:<78} |\n"
        result_str += f"╰─{' '*78}─╯"
        return result_str

    search_results = fetch_social_urls(urls, "Deep Account Search")
    Write.Print(search_results, Colors.white, interval=0)
    log_option(search_results)

    print("[?] Export deep account search to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"nickname": nickname, "results": search_results}, filename_prefix="deep_account_search")
    restart()

def phone_info(phone_number):
    try:
        parsed_number = phonenumbers.parse(phone_number)
        country = geocoder.country_name_for_number(parsed_number, "en")
        region = geocoder.description_for_number(parsed_number, "en")
        operator = carrier.name_for_number(parsed_number, "en") if carrier else "" #the fix
        valid = phonenumbers.is_valid_number(parsed_number)
        validity = "Valid" if valid else "Invalid"
        phonetext = f"""
╭─{' '*50}─╮
|{' '*17}Phone number info{' '*18}|
|{'='*52}|
| [+] > Number   || {phone_number:<33}|
| [+] > Country  || {country:<33}     |
| [+] > Region   || {region:<33}      |
| [+] > Operator || {operator:<33}    |
| [+] > Validity || {validity:<33}    |
╰─{' '*15}─╯╰─{' '*31}─╯
"""
        Write.Print(phonetext, Colors.white, interval=0)
        log_option(phonetext)

        print("[?] Export phone info to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({
                "phone_number": phone_number,
                "country": country,
                "region": region,
                "operator": operator,
                "validity": validity
            }, filename_prefix="phone_info")

    except phonenumbers.phonenumberutil.NumberParseException:
        clear()
        Write.Print(f"\n[!] > Error: invalid phone number format (+1-000-000-0000)", default_color, interval=0)
    restart()

def reverse_phone_lookup(phone_number: str):
    base_prompt = (
        "You are a reverse-phone-lookup analyst.\n\n"
        "Task: identify the person or business most often linked to a given number.\n"
        "Return only publicly sourced facts, covering:\n"
        "• Name / aliases or business name\n"
        "• Primary location or address\n"
        "• Roles, affiliations, or industry context\n"
        "• Any other verifiable public details\n\n"
        "Flag uncertainties, rate confidence, and suggest ways to confirm doubtful data. "
        "If information is insufficient or ambiguous, ask for clarification or perform a forward search (name → numbers). "
        "Prioritise accuracy, transparency, privacy, and source integrity."
    )

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": f"Perform a reverse lookup for: {phone_number}"}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True
    }
    
    PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
    PERPLEXITY_API_KEY = "INSERT API KEY HERE"
    perplexity_headers = {
        "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
        "Content-Type": "application/json",
    }

    api_content = ""
    results_text = ""
    
    try:
        response = requests.post(
            PERPLEXITY_API_URL,
            headers=perplexity_headers,
            json=payload,
            stream=True,
            timeout=160
        )
        if response.status_code == 200:
            header = (
                f"╭─{' ' * 78}─╮\n"
                f"|{' ' * 28}Reverse Phone Lookup{' ' * 28}|\n"
                f"|{'=' * 80}|\n"
                f"| [+] > Query: {phone_number:<66}|\n"
                f"|{'-' * 80}|\n"
            )
            print(header, end="")
            results_text += header

            for line in response.iter_lines():
                if line:
                    try:
                        decoded_line = line.decode("utf-8").strip()
                        if decoded_line.startswith("data: "):
                            data_str = decoded_line[len("data: "):].strip()
                            if data_str == "[DONE]":
                                break
                            data_chunk = json.loads(data_str)
                            content_chunk = data_chunk["choices"][0].get("delta", {}).get("content", "")
                            if content_chunk:
                                print(content_chunk, end="", flush=True)
                                results_text += content_chunk
                                api_content += content_chunk
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        results_text += error_msg
        else:
            error_msg = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
            print(error_msg)
            results_text += error_msg
    except Exception as e:
        error_msg = f"[!] > Error: {str(e)}\n"
        print(error_msg)
        results_text += error_msg

    footer = f"\n╰─{' ' * 78}─╯\n"
    print(footer)
    results_text += footer

    clear()
    Write.Print(results_text, Colors.white, interval=0)
    log_option(results_text)
    print("[?] Export reverse phone lookup to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"phone_number": phone_number, "data": api_content}, filename_prefix="reverse_phone_lookup")
    restart()


def dns_lookup(domain):
    record_types = ['A', 'CNAME', 'MX', 'NS']
    result_output = f"""
╭─{' '*78}─╮
|{' '*33} DNS Lookup {' '*33}|
|{'='*80}|
"""
    for rtype in record_types:
        result_output += f"| [+] > {rtype} Records: {' '*62}|\n"
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for ans in answers:
                if rtype == 'MX':
                    result_output += f"|    {ans.preference:<4} {ans.exchange:<70}|\n"
                else:
                    result_output += f"|    {str(ans):<76}|\n"
        except dns.resolver.NoAnswer:
            result_output += "|    No records found.\n"
        except dns.resolver.NXDOMAIN:
            result_output += "|    Domain does not exist.\n"
        except Exception:
            result_output += "|    Error retrieving records.\n"
        result_output += f"|{'='*80}|\n"
    result_output += f"╰─{' '*78}─╯"
    Write.Print(result_output, Colors.white, interval=0)
    log_option(result_output)

    print("[?] Export DNS lookup to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"domain": domain, "dns_records_raw": result_output}, filename_prefix="dns_lookup")

    restart()

def email_lookup(email_address):
    try:
        v = validate_email(email_address)
        email_domain = v.domain
    except EmailNotValidError as e:
        Write.Print(f"[!] > Invalid email address format: {str(e)}", default_color, interval=0)
        restart()
        return
    mx_records = []
    try:
        answers = dns.resolver.resolve(email_domain, 'MX')
        for rdata in answers:
            mx_records.append(str(rdata.exchange))
    except:
        mx_records = []
    validity = "Mx Found (Might be valid)" if mx_records else "No MX found (Might be invalid)"
    email_text = f"""
╭─{' '*78}─╮
|{' '*34}Email Info{' '*34}|
|{'='*80}|
| [+] > Email:        || {email_address:<52}|
| [+] > Domain:       || {email_domain:<52}|
| [+] > MX Records:   || {", ".join(mx_records) if mx_records else "None":<52}|
| [+] > Validity:     || {validity:<52}|
╰─{' '*23}─╯╰─{' '*51}─╯
"""
    Write.Print(email_text, Colors.white, interval=0)
    log_option(email_text)

    print("[?] Export email lookup to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({
            "email": email_address,
            "domain": email_domain,
            "mx_records": mx_records,
            "validity": validity
        }, filename_prefix="email_lookup")

    restart()

def reverse_dns(ip):
    try:
        rev_name = reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        ptr_record = str(answers[0]).strip('.')
    except:
        ptr_record = "No PTR record found"
    rdns_text = f"""
╭─{' '*78}─╮
|{' '*33}Reverse DNS Lookup{' '*33}|
|{'='*80}|
| [+] > IP:     || {ip:<60}|
| [+] > Host:   || {ptr_record:<60}|
╰─{' '*23}─╯╰─{' '*51}─╯
"""
    Write.Print(rdns_text, Colors.white, interval=0)
    log_option(rdns_text)

    print("[?] Export reverse DNS to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"ip": ip, "ptr_record": ptr_record}, filename_prefix="reverse_dns")

    restart()

def analyze_email_header(raw_headers):
    parser = Parser()
    msg = parser.parsestr(raw_headers)
    from_ = msg.get("From", "")
    to_ = msg.get("To", "")
    subject_ = msg.get("Subject", "")
    date_ = msg.get("Date", "")
    received_lines = msg.get_all("Received", [])
    found_ips = []
    if received_lines:
        for line in received_lines:
            potential_ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            for ip in potential_ips:
                if ip not in found_ips:
                    found_ips.append(ip)

    header_text = f"""
╭─{' '*78}─╮
|{' '*31}Email Header Analysis{' '*31}|
|{'='*80}|
| [+] > From:      || {from_:<55}|
| [+] > To:        || {to_:<55}|
| [+] > Subject:   || {subject_:<55}|
| [+] > Date:      || {date_:<55}|
|{'-'*80}|
"""
    if found_ips:
        header_text += "| [+] > Received Path (IPs found):\n"
        for ip in found_ips:
            header_text += f"|    {ip:<76}|\n"
    else:
        header_text += "| [+] > No IPs found in Received headers.\n"
    header_text += f"╰─{' '*78}─╯"
    Write.Print(header_text, Colors.white, interval=0)

    ip_details_full = ""
    if found_ips:
        ip_details_header = f"""
╭─{' '*78}─╮
|{' '*30}IP Geolocation Details{' '*30}|
|{'='*80}|
"""
        ip_details_summary = ""
        for ip in found_ips:
            data = get_ip_details(ip)
            if data is not None:
                loc = data.get('loc', 'None')
                ip_details_summary += f"| IP: {ip:<14}|| City: {data.get('city','N/A'):<15} Region: {data.get('region','N/A'):<15} Country: {data.get('country','N/A'):<4}|\n"
                ip_details_summary += f"|    Org: {data.get('org','N/A'):<63}|\n"
                ip_details_summary += f"|    Loc: {loc:<63}|\n"
                ip_details_summary += "|" + "-"*78 + "|\n"
            else:
                ip_details_summary += f"| IP: {ip:<14}|| [!] Could not retrieve details.\n"
                ip_details_summary += "|" + "-"*78 + "|\n"
        ip_details_footer = f"╰─{' '*78}─╯"
        ip_details_full = ip_details_header + ip_details_summary + ip_details_footer
        Write.Print(ip_details_full, Colors.white, interval=0)

    spf_result, dkim_result, dmarc_result = None, None, None
    spf_domain, dkim_domain = None, None
    auth_results = msg.get_all("Authentication-Results", [])
    from_domain = ""
    if "@" in from_:
        from_domain = from_.split("@")[-1].strip(">").strip()
    if auth_results:
        for entry in auth_results:
            spf_match = re.search(r'spf=(pass|fail|softfail|neutral)', entry, re.IGNORECASE)
            if spf_match:
                spf_result = spf_match.group(1)
            spf_domain_match = re.search(r'envelope-from=([^;\s]+)', entry, re.IGNORECASE)
            if spf_domain_match:
                spf_domain = spf_domain_match.group(1)
            dkim_match = re.search(r'dkim=(pass|fail|none|neutral)', entry, re.IGNORECASE)
            if dkim_match:
                dkim_result = dkim_match.group(1)
            dkim_domain_match = re.search(r'd=([^;\s]+)', entry, re.IGNORECASE)
            if dkim_domain_match:
                dkim_domain = dkim_domain_match.group(1)
            dmarc_match = re.search(r'dmarc=(pass|fail|none)', entry, re.IGNORECASE)
            if dmarc_match:
                dmarc_result = dmarc_match.group(1)
    spf_align = False
    dkim_align = False
    if from_domain and spf_domain:
        spf_align = from_domain.lower() == spf_domain.lower()
    if from_domain and dkim_domain:
        dkim_align = from_domain.lower() == dkim_domain.lower()
    alignment_text = f"""
╭─{' '*78}─╮
|{' '*30}SPF / DKIM / DMARC Checks{' '*29}|
|{'='*80}|
| [+] > SPF  Result:   {spf_result if spf_result else 'Not found':<20}   Domain: {spf_domain if spf_domain else 'N/A':<20} Aligned: {spf_align}|
| [+] > DKIM Result:   {dkim_result if dkim_result else 'Not found':<20} Domain: {dkim_domain if dkim_domain else 'N/A':<20} Aligned: {dkim_align}|
| [+] > DMARC Result:  {dmarc_result if dmarc_result else 'Not found':<20}|
╰─{' '*78}─╯
"""
    Write.Print(alignment_text, Colors.white, interval=0)
    full_output = header_text + "\n" + ip_details_full + "\n" + alignment_text
    log_option(full_output)

    print("[?] Export email header analysis to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({
            "raw_headers": raw_headers,
            "from": from_,
            "to": to_,
            "subject": subject_,
            "date": date_,
            "found_ips": found_ips,
            "spf_result": spf_result,
            "spf_domain": spf_domain,
            "spf_aligned": spf_align,
            "dkim_result": dkim_result,
            "dkim_domain": dkim_domain,
            "dkim_aligned": dkim_align,
            "dmarc_result": dmarc_result
        }, filename_prefix="email_header_analysis")
    restart()

def haveibeenpwned_check(email):
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    try:
        resp = requests.get(url, headers=headers, timeout=60)
        if resp.status_code == 200:
            breaches = resp.json()
            clear()
            results_text = f"""
╭─{' '*78}─╮
|{' '*30}Have I Been Pwned?{' '*30}|
|{'='*80}|
| [!] > Bad news! Your email was found in {len(breaches)} breach(es)                          |
|{'-'*80}|
"""
            for index, breach in enumerate(breaches, start=1):
                breach_name = breach.get('Name', 'Unknown')
                domain = breach.get('Domain', 'Unknown')
                breach_date = breach.get('BreachDate', 'Unknown')
                added_date = breach.get('AddedDate', 'Unknown')
                pwn_count = breach.get('PwnCount', 'Unknown')
                data_classes = ", ".join(breach.get('DataClasses', []))
                results_text += f"| Breach #{index}: {breach_name:<66}|\n"
                results_text += f"|    Domain: {domain:<71}|\n"
                results_text += f"|    Breach Date: {breach_date:<65}|\n"
                results_text += f"|    Added Date:  {added_date:<65}|\n"
                results_text += f"|    PwnCount:    {pwn_count:<65}|\n"
                results_text += f"|    Data Types:  {data_classes:<65}|\n"
                results_text += f"|{'='*80}|\n"
            results_text += f"╰─{' '*78}─╯"
            Write.Print(results_text, Colors.white, interval=0)
            log_option(results_text)

            print("[?] Export breach info to JSON? (Y/N): ", end="")
            if input().strip().upper() == "Y":
                export_json({"email": email, "breaches": breaches}, filename_prefix="breach_info")

        elif resp.status_code == 404:
            clear()
            msg = f"""
╭─{' '*78}─╮
|{' '*30}Have I Been Pwned?{' '*30}|
|{'='*80}|
| [!] > Good news! No breaches found for: {email:<48}|
╰─{' '*78}─╯
"""
            Write.Print(msg, Colors.white, interval=0)
            log_option(msg)
        else:
            clear()
            error_msg = f"[!] > An error occurred: HTTP {resp.status_code}\nResponse: {resp.text}\n"
            Write.Print(error_msg, Colors.red, interval=0)
            log_option(error_msg)
    except requests.exceptions.Timeout:
        clear()
        Write.Print("[!] > Request timed out when contacting Have I Been Pwned.", default_color, interval=0)
    except Exception as e:
        clear()
        Write.Print(f"[!] > An error occurred: {str(e)}", default_color, interval=0)
    restart()

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        clear()
        domain_name = w.domain_name if w.domain_name else "N/A"
        registrar = w.registrar if w.registrar else "N/A"
        creation_date = w.creation_date if w.creation_date else "N/A"
        expiration_date = w.expiration_date if w.expiration_date else "N/A"
        updated_date = w.updated_date if w.updated_date else "N/A"
        name_servers = ", ".join(w.name_servers) if w.name_servers else "N/A"
        status = ", ".join(w.status) if w.status else "N/A"
        whois_text = f"""
╭─{' '*78}─╮
|{' '*34}WHOIS Lookup{' '*34}|
|{'='*80}|
| [+] > Domain Name:       || {str(domain_name):<52}|
| [+] > Registrar:         || {str(registrar):<52}|
| [+] > Creation Date:     || {str(creation_date):<52}|
| [+] > Expiration Date:   || {str(expiration_date):<52}|
| [+] > Updated Date:      || {str(updated_date):<52}|
| [+] > Name Servers:      || {name_servers:<52}|
| [+] > Status:            || {status:<52}|
╰─{' '*23}─╯╰─{' '*51}─╯
"""
        Write.Print(whois_text, Colors.white, interval=0)
        log_option(whois_text)

        print("[?] Export WHOIS to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            data = {
                "domain": domain,
                "domain_name": str(domain_name),
                "registrar": str(registrar),
                "creation_date": str(creation_date),
                "expiration_date": str(expiration_date),
                "updated_date": str(updated_date),
                "name_servers": name_servers,
                "status": status
            }
            export_json(data, filename_prefix="whois_lookup")
    except Exception as e:
        clear()
        Write.Print(f"[!] > WHOIS lookup error: {str(e)}", default_color, interval=0)
    restart()

def check_password_strength(password):
    txt_file_path = os.path.join(os.path.dirname(__file__), "passwords.txt")
    if os.path.isfile(txt_file_path):
        try:
            with open(txt_file_path, "r", encoding="utf-8") as f:
                common_words = [line.strip() for line in f if line.strip()]
            for word in common_words:
                if word and word.lower() in password.lower():
                    return (
                        "Weak password (contains or overlaps with a common word/phrase/sequence, "
                        "DO NOT use this password)"
                    )
        except Exception as e:
            pass

    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[^a-zA-Z0-9]', password):
        score += 1

    if score <= 2:
        return "Weak password (too short or lacks variety, DO NOT use this password)"
    elif 3 <= score <= 4:
        return "Moderate password (room for improvement)"
    else:
        return "Strong password (suitable for high security apps/credentials)"

def password_strength_tool():
    clear()
    Write.Print("[!] > Enter password to evaluate strength:\n", Colors.white, interval=0)
    password = Write.Input("[?] >  ", Colors.white, interval=0)
    if not password:
        clear()
        Write.Print("[!] > Password cannot be empty. Please enter the password.\n", Colors.white, interval=0)
        restart()
        return
    strength = check_password_strength(password)
    clear()
    output_text = f"Password Strength: {strength}\n"
    Write.Print(output_text, Colors.white, interval=0)
    log_option(output_text)
    restart()

def username_check():
    clear()
    Write.Print("[!] > Conducting Username Check...\n", default_color, interval=0)
    username = Write.Input("[?] > Enter the username: ", default_color, interval=0).strip()
    if not username:
        clear()
        Write.Print("[!] > No username provided.\n", Colors.red, interval=0)
        restart()
        return

    def fetch_wmn_data():
        try:
            response = requests.get("https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json", timeout=60)
            response.raise_for_status()
            return response.json()
        except:
            Write.Print("[!] > Failed to fetch data from WhatsMyName repository.\n", Colors.red, interval=0)
            return None

    data = fetch_wmn_data()
    if not data:
        restart()
        return

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
    }
    sites = data["sites"]
    total_sites = len(sites)
    found_sites = []
    output_accumulated = ""

    def check_site(site, username, headers):
        site_name = site["name"]
        uri_check = site["uri_check"].format(account=username)
        try:
            res = requests.get(uri_check, headers=headers, timeout=60)
            estring_pos = site["e_string"] in res.text
            estring_neg = site["m_string"] in res.text
            if res.status_code == site["e_code"] and estring_pos and not estring_neg:
                return site_name, uri_check
        except:
            pass
        return None

    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_site, site, username, headers): site for site in sites}
            with tqdm(total=total_sites, desc="Checking sites") as pbar:
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            site_name, uri_check = result
                            found_sites.append((site_name, uri_check))
                            found_str = f"[+] Found on: {site_name}\n[+] Profile URL: {uri_check}\n"
                            output_accumulated += found_str
                            Write.Print(found_str, Colors.green, interval=0)
                    except Exception:
                        pass
                    finally:
                        pbar.update(1)
        if found_sites:
            summary_str = f"\n[!] > Username found on {len(found_sites)} sites!\n"
            output_accumulated += summary_str
            Write.Print(summary_str, Colors.green, interval=0)

            generate_html_report(username, found_sites)
            report_msg = f"\n[!] > Report saved: username_check_report_{username}.html\n"
            output_accumulated += report_msg
            Write.Print(report_msg, Colors.green, interval=0)
        else:
            no_result_str = f"[!] > No results found for {username}.\n"
            output_accumulated += no_result_str
            Write.Print(no_result_str, Colors.red, interval=0)
    except Exception as e:
        err_str = f"[!] > An error occurred: {str(e)}\n"
        output_accumulated += err_str
        Write.Print(err_str, Colors.red, interval=0)

    log_option(output_accumulated)
    print("[?] Export username check to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"username": username, "found_sites": found_sites}, filename_prefix="username_check")
    restart()

def generate_html_report(username, found_sites):
    html_content = f"""
<html>
<head>
    <title>Username Check Report for {username}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
    </style>
</head>
<body>
    <h1>Username Check Report for {username}</h1>
    <table>
        <tr>
            <th>Website Name</th>
            <th>Profile URL</th>
        </tr>
"""
    for site_name, uri_check in found_sites:
        html_content += f"""
        <tr>
            <td>{site_name}</td>
            <td><a href="{uri_check}" target="_blank">{uri_check}</a></td>
        </tr>"""
    html_content += """
    </table>
</body>
</html>"""
    with open(f"username_check_report_{username}.html", "w") as report_file:
        report_file.write(html_content)

def check_ssl_cert(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=60) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject.get('commonName', 'N/A')
        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer.get('commonName', 'N/A')
        not_before = cert['notBefore']
        not_after = cert['notAfter']
        not_before_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        not_after_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        info_text = f"""
╭─{' '*78}─╮
|{' '*33}SSL Certificate Info{' '*32}|
|{'='*80}|
| [+] > Domain:       {domain:<58}|
| [+] > Issued To:    {issued_to:<58}|
| [+] > Issued By:    {issued_by:<58}|
| [+] > Valid From:   {str(not_before_dt):<58}|
| [+] > Valid Until:  {str(not_after_dt):<58}|
╰─{' '*78}─╯
"""
        Write.Print(info_text, Colors.white, interval=0)
        log_option(info_text)

        print("[?] Export SSL info to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({
                "domain": domain,
                "issued_to": issued_to,
                "issued_by": issued_by,
                "valid_from": str(not_before_dt),
                "valid_until": str(not_after_dt)
            }, filename_prefix="ssl_info")

    except ssl.SSLError as e:
        Write.Print(f"[!] > SSL Error: {str(e)}\n", Colors.red, interval=0)
    except socket.timeout:
        Write.Print("[!] > Connection timed out.\n", Colors.red, interval=0)
    except Exception as e:
        Write.Print(f"[!] > An error occurred retrieving SSL cert info: {str(e)}\n", Colors.red, interval=0)
    restart()

def check_robots_and_sitemap(domain):
    urls = [
        f"https://{domain}/robots.txt",
        f"https://{domain}/sitemap.xml"
    ]
    result_text = f"""
╭─{' '*78}─╮
|{' '*32}Site Discovery{' '*32}|
|{'='*80}|
| [+] > Domain:  {domain:<63}|
|{'-'*80}|
"""
    for resource_url in urls:
        try:
            resp = requests.get(resource_url, timeout=60)
            if resp.status_code == 200:
                lines = resp.text.split('\n')
                result_text += f"| Resource: {resource_url:<66}|\n"
                result_text += f"| Status: 200 (OK)\n"
                result_text += f"|{'-'*80}|\n"
                snippet = "\n".join(lines[:10])
                snippet_lines = snippet.split('\n')
                for sline in snippet_lines:
                    trunc = sline[:78]
                    result_text += f"| {trunc:<78}|\n"
                if len(lines) > 10:
                    result_text += "| ... (truncated)\n"
            else:
                result_text += f"| Resource: {resource_url:<66}|\n"
                result_text += f"| Status: {resp.status_code}\n"
            result_text += f"|{'='*80}|\n"
        except requests.exceptions.RequestException as e:
            result_text += f"| Resource: {resource_url}\n"
            result_text += f"| Error: {str(e)}\n"
            result_text += f"|{'='*80}|\n"
    result_text += f"╰─{' '*78}─╯"
    Write.Print(result_text, Colors.white, interval=0)
    log_option(result_text)

    print("[?] Export robots/sitemap to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"domain": domain, "discovery": result_text}, filename_prefix="site_discovery")
    restart()

def check_dnsbl(ip_address):
    dnsbl_list = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org"
    ]
    reversed_ip = ".".join(ip_address.split(".")[::-1])
    results = []
    for dnsbl in dnsbl_list:
        query_domain = f"{reversed_ip}.{dnsbl}"
        try:
            answers = dns.resolver.resolve(query_domain, 'A')
            for ans in answers:
                results.append((dnsbl, str(ans)))
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except Exception as e:
            results.append((dnsbl, f"Error: {str(e)}"))
    report = f"""
╭─{' '*78}─╮
|{' '*33}DNSBL Check{' '*34}|
|{'='*80}|
| [+] > IP: {ip_address:<67}|
|{'-'*80}|
"""
    if results:
        report += "| The IP is listed on the following DNSBL(s):\n"
        for dnsbl, answer in results:
            report += f"|   {dnsbl:<25} -> {answer:<45}|\n"
    else:
        report += "| The IP is NOT listed on the tested DNSBL(s).\n"
    report += f"╰─{' '*78}─╯"
    Write.Print(report, Colors.white, interval=0)
    log_option(report)

    print("[?] Export DNSBL check to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"ip_address": ip_address, "dnsbl_results": results}, filename_prefix="dnsbl_check")
    restart()

def fetch_webpage_metadata(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=60)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")
        title_tag = soup.find("title")
        meta_desc = soup.find("meta", attrs={"name": "description"})
        meta_keyw = soup.find("meta", attrs={"name": "keywords"})
        title = title_tag.get_text(strip=True) if title_tag else "N/A"
        description = meta_desc["content"] if meta_desc and "content" in meta_desc.attrs else "N/A"
        keywords = meta_keyw["content"] if meta_keyw and "content" in meta_keyw.attrs else "N/A"
        result_text = f"""
╭─{' '*78}─╮
|{' '*31}Webpage Metadata{' '*31}|
|{'='*80}|
| [+] > URL:         {url:<58}|
| [+] > Title:       {title:<58}|
| [+] > Description: {description:<58}|
| [+] > Keywords:    {keywords:<58}|
╰─{' '*78}─╯
"""
        Write.Print(result_text, Colors.white, interval=0)
        log_option(result_text)

        print("[?] Export webpage metadata to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({
                "url": url,
                "title": title,
                "description": description,
                "keywords": keywords
            }, filename_prefix="webpage_metadata")
    except Exception as e:
        Write.Print(f"[!] > Error fetching metadata: {str(e)}\n", Colors.red, interval=0)
    restart()

PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
PERPLEXITY_API_KEY = "INSERT API KEY HERE"
perplexity_headers = {
    "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
    "Content-Type": "application/json",
}

def business_search():
    clear()
    Write.Print("[!] > Retrieve information about a business.\n", default_color, interval=0)
    business_name = Write.Input("[?] > Enter the business or person’s name to search: ",
                                default_color, interval=0).strip()
    if not business_name:
        Write.Print("[!] > No business name was provided.\n", Colors.red, interval=0)
        restart()
        return

    base_prompt = (
        "You are a business-intelligence assistant.\n\n"
        "Task: compile a structured, source-cited dossier on the named organisation.\n"
        "Include:\n"
        "• Legal name / aliases, HQ and other key sites\n"
        "• Leadership, ownership, employee count\n"
        "• Core financials (revenue, profit, valuation) or best estimates\n"
        "• Public contact details (phone, email, postal, web)\n"
        "• Market position, principal competitors, and industry / regulatory trends\n"
        "• Opportunities, risks, and actionable strategic recommendations\n\n"
        "Cite every fact, separate verified data from analysis, and flag any gaps or uncertainties."
    )

    payload_business_info = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": f"Provide me with general information about {business_name}."}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True
    }
    out_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_business_info, stream=True)
        if response.status_code == 200:
            header = "\nGeneral Business Information:\n"
            print(header, end="")
            out_text += header

            for line in response.iter_lines():
                if line:
                    try:
                        decoded_line = line.decode("utf-8").strip()
                        if decoded_line.startswith("data: "):
                            data_str = decoded_line[len("data: "):].strip()
                            if data_str == "[DONE]":
                                break
                            data_chunk = json.loads(data_str)
                            content_chunk = data_chunk["choices"][0].get("delta", {}).get("content", "")
                            if content_chunk:
                                print(content_chunk, end="", flush=True)
                                out_text += content_chunk
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        out_text += error_msg
        else:
            err_msg = f"Error: {response.status_code}, {response.text}\n"
            print(err_msg)
            out_text += err_msg
    except Exception as e:
        out_text = f"[!] > Exception in retrieving business info: {str(e)}\n"
        print(out_text)
    log_option(out_text)
    restart()


def business_reputation_search():
    clear()
    Write.Print("[!] > Business Reputation Search\n", default_color, interval=0)
    company_name = Write.Input("[?] > Enter Company Name: ", default_color, interval=0).strip()
    if not company_name:
        clear()
        Write.Print("[!] > Company name is required.\n", Colors.red, interval=0)
        restart()
        return

    base_prompt_reputation = (
        "Please provide a comprehensive risk assessment for " + company_name +
        " covering the period from + start_date + to present. Include any documented incidents, regulatory violations, compliance issues, legal proceedings, and public controversies. "
        "Focus on areas that could impact business continuity, reputation, or contractual obligations, including but not limited to: data breaches, cybersecurity incidents, environmental violations, labor disputes, financial irregularities, chain disruptions, product quality issues, and regulatory non-compliance. "
        "Detail the nature of each incident, its resolution status, any penalties or settlements imposed, and implemented remediation measures. Additionally, highlight any patterns of recurring issues or systemic problems. You must cite all sources in Chicago format."
    )

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt_reputation},
            {"role": "user", "content": f"Conduct a comprehensive business reputation analysis for {company_name}."}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True 
    }

    result_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, stream=True, timeout=60)
        if response.status_code == 200:
            header = "\nBusiness Reputation Analysis:\n"
            print(header, end="")
            result_text += header

            for line in response.iter_lines():
                if line:
                    try:
                        decoded_line = line.decode("utf-8").strip()
                        if decoded_line.startswith("data: "):
                            data_str = decoded_line[len("data: "):].strip()
                            if data_str == "[DONE]":
                                break
                            data_chunk = json.loads(data_str)
                            content_chunk = data_chunk["choices"][0].get("delta", {}).get("content", "")
                            if content_chunk:
                                print(content_chunk, end="", flush=True)
                                result_text += content_chunk
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        result_text += error_msg
        else:
            result_text = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
            print(result_text)
    except Exception as e:
        result_text = f"[!] > Exception in retrieving business reputation info: {str(e)}\n"
        print(result_text)
    log_option(result_text)
    restart()

def travel_assessment(location):
    clear()
    Write.Print("[!] > Creating a comprehensive travel risk analysis...\n", default_color, interval=0)
    analysis = ""
    prompt = f"""
Provide a comprehensive, highly detailed travel risk analysis for the following location: {location}...
"""
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a travel risk analysis assistant specializing in providing comprehensive, detailed, and practical risk assessments for travel destinations. "
                    "Your responses should cover political stability, crime rates, natural disasters, health risks, local laws, infrastructure, and other relevant factors. "
                    "Ensure that your analysis is thorough, well-structured, and includes practical advice, best practices, and necessary disclaimers with clear citations if applicable."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True  
    }
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, stream=True, timeout=60)
        if response.status_code == 200:
            for line in response.iter_lines():
                if line:
                    try:
                        decoded_line = line.decode("utf-8").strip()
                        if decoded_line.startswith("data: "):
                            data_str = decoded_line[len("data: "):].strip()
                            if data_str == "[DONE]":
                                break
                            data_chunk = json.loads(data_str)
                            content_chunk = data_chunk["choices"][0].get("delta", {}).get("content", "")
                            if content_chunk:
                                print(content_chunk, end="", flush=True)
                                analysis += content_chunk
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        analysis += error_msg
        else:
            analysis = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
            Write.Print(analysis, Colors.red, interval=0)
    except Exception as e:
        analysis = f"[!] > An error occurred: {str(e)}\n"
        Write.Print(analysis, Colors.red, interval=0)
    log_option(analysis)
    restart()

def botometer_search():
    clear()
    username = Write.Input("[?] > Enter a X/Twitter username (with or without @): ", default_color, interval=0).strip()
    if not username:
        Write.Print("[!] > No username was provided.\n", Colors.red, interval=0)
        restart()
        return
    if not username.startswith("@"):
        username = "@" + username
    Write.Print(f"[!] > Checking Botometer score for {username}...\n", default_color, interval=0)
    output_text = ""
    try:
        url = "https://botometer-pro.p.rapidapi.com/botometer-x/get_botscores_in_batch"
        payload = {
            "user_ids": [],
            "usernames": [username]
        }
        headers = {
            "x-rapidapi-key": "INSERT API KEY HERE",
            "x-rapidapi-host": "botometer-pro.p.rapidapi.com",
            "Content-Type": "application/json"
        }
        response = requests.post(url, json=payload, headers=headers, timeout=60)
        result = response.json()
        output_text = json.dumps(result, indent=2)
        Write.Print(output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > An error occurred: {str(e)}"
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def hudson_rock_email_infection_check():
    clear()
    email = Write.Input("[?] > Enter an email to check infection status: ", default_color, interval=0).strip()
    if not email:
        clear()
        Write.Print("[!] > No email was provided.\n", Colors.red, interval=0)
        restart()
        return
    output_text = ""
    try:
        url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
        params = {"email": email}
        resp = requests.get(url, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        output_lines = [f"[+] Hudson Rock email infection check results for {email}:\n"]
        if isinstance(data, dict):
            for k, v in data.items():
                output_lines.append(f"{k}: {v}")
        else:
            output_lines.append("No structured data available.")
        output_text = "\n".join(output_lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except requests.exceptions.Timeout:
        output_text = "[!] > Request timed out when contacting Hudson Rock.\n"
        clear()
        Write.Print(output_text, default_color, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, default_color, interval=0)
    log_option(output_text)
    restart()

def hudson_rock_username_infection_check():
    clear()
    username = Write.Input("[?] > Enter a username to check infection status: ", default_color, interval=0).strip()
    if not username:
        clear()
        Write.Print("[!] > No username was provided.\n", Colors.red, interval=0)
        restart()
        return
    output_text = ""
    try:
        url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username"
        params = {"username": username}
        resp = requests.get(url, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        output_lines = [f"[+] Hudson Rock username infection check results for {username}:\n"]
        if isinstance(data, dict):
            for k, v in data.items():
                output_lines.append(f"{k}: {v}")
        else:
            output_lines.append("No structured data available.")
        output_text = "\n".join(output_lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except requests.exceptions.Timeout:
        output_text = "[!] > Request timed out when contacting Hudson Rock.\n"
        clear()
        Write.Print(output_text, default_color, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, default_color, interval=0)
    log_option(output_text)
    restart()

def hudson_rock_domain_infection_check():
    clear()
    domain = Write.Input("[?] > Enter a domain / URL to check infection status: ", default_color, interval=0).strip()
    if not domain:
        clear()
        Write.Print("[!] > No domain was provided.\n", Colors.red, interval=0)
        restart()
        return
    output_text = ""
    try:
        url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
        params = {"domain": domain}
        resp = requests.get(url, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        output_lines = [f"[+] Hudson Rock domain infection check results for {domain}:\n"]
        if isinstance(data, dict):
            for k, v in data.items():
                output_lines.append(f"{k}: {v}")
        else:
            output_lines.append("No structured data available.")
        output_text = "\n".join(output_lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except requests.exceptions.Timeout:
        output_text = "[!] > Request timed out when contacting Hudson Rock.\n"
        clear()
        Write.Print(output_text, default_color, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, default_color, interval=0)
    log_option(output_text)
    restart()

def hudson_rock_ip_infection_check():
    clear()
    ip_address = Write.Input("[?] > Enter IP address to check infection status: ", default_color, interval=0).strip()
    if not ip_address:
        clear()
        Write.Print("[!] > No IP provided.\n", Colors.red, interval=0)
        restart()
        return
    output_text = ""
    try:
        url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-ip"
        params = {"ip": ip_address}
        resp = requests.get(url, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        output_lines = [f"[+] Hudson Rock IP infection check results for {ip_address}:\n"]
        if isinstance(data, dict):
            for k, v in data.items():
                output_lines.append(f"{k}: {v}")
        else:
            output_lines.append("No structured data available.")
        output_text = "\n".join(output_lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except requests.exceptions.Timeout:
        output_text = "[!] > Request timed out when contacting Hudson Rock.\n"
        clear()
        Write.Print(output_text, default_color, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, default_color, interval=0)
    log_option(output_text)
    restart()

def fact_check_text():
    clear()
    Write.Print("[!] > Enter text to fact-check:\n", default_color, interval=0)
    text_to_check = Write.Input("[?] >  ", default_color, interval=0).strip()
    if not text_to_check:
        clear()
        Write.Print("[!] > No text was provided.\n", Colors.red, interval=0)
        restart()
        return

    base_prompt = (
        "You are a fact-check analyst.\n\n"
        "Task: evaluate the accuracy of the supplied passage.\n"
        "For each distinct claim:\n"
        "• State whether it is True, False, Partly True, or Unclear.\n"
        "• Provide a one-sentence justification.\n"
        "• Note any missing context, cherry-picking, emotive or biased language.\n"
        "• Flag alternative explanations or perspectives.\n\n"
        "Verification rules: consult multiple independent, authoritative sources; cross-check dates, numbers, and quoted text; "
        "highlight inconsistencies. Prioritise primary documents, peer-reviewed research, government or court records, and reputable media.\n\n"
        "Citations: number each source as [#] inline and conclude with a Chicago-style bibliography. "
        "If evidence is insufficient, say so and rate confidence."
    )

    payload_fact_check = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": f"Fact-check the following text:\n\n{text_to_check}"},
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True,
    }

    output_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_fact_check, stream=True, timeout=60)
        if response.status_code == 200:
            header = "\nFact Checking Results:\n"
            print(header, end="")
            output_text += header
            for line in response.iter_lines():
                if line:
                    try:
                        decoded_line = line.decode("utf-8").strip()
                        if decoded_line.startswith("data: "):
                            data_str = decoded_line[len("data: "):].strip()
                            if data_str == "[DONE]":
                                break
                            data_chunk = json.loads(data_str)
                            content_chunk = data_chunk["choices"][0].get("delta", {}).get("content", "")
                            if content_chunk:
                                print(content_chunk, end="", flush=True)
                                output_text += content_chunk
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        output_text += error_msg
        else:
            err_msg = f"Error: {response.status_code}, {response.text}\n"
            print(err_msg)
            output_text += err_msg
    except Exception as e:
        err_msg = f"[!] > Exception in fact-checking: {str(e)}\n"
        print(err_msg)
        output_text += err_msg

    log_option(output_text)
    restart()

def relationship_search():
    clear()
    Write.Print("[!] > Analyze relationships between people, organizations, or businesses:\n",
                default_color, interval=0)
    query = Write.Input("[?] > Enter your query: ", default_color, interval=0).strip()
    if not query:
        Write.Print("[!] > No query provided.\n", Colors.red, interval=0)
        restart()
        return

    base_prompt = (
        "You are a relationship-mapping analyst.\n\n"
        "Task: create a fully sourced dossier on the entities in the query, covering:\n"
        "• Brief subject overview\n"
        "• Categorised links (business, personal, philanthropic, etc.)\n"
        "• Timeline of key interactions (with dates)\n"
        "• Evidence-based assessment of each link’s strength, relevance, and any conflicts/red flags\n"
        "• High-level network map of direct and indirect ties\n\n"
        "Guidelines: cite every fact inline as [#]; separate verified data from inference; omit un-sourced claims; "
        "use primary documents, filings, or reputable media; flag speculation or data gaps. "
        "End with: ‘Sources:’ plus numbered Chicago-style references."
    )

    payload_relationships = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": query}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True
    }

    output_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_relationships, stream=True)
        if response.status_code == 200:
            header = "\nEntity Relationship Analysis Results:\n"
            print(header, end="")
            output_text += header

            for line in response.iter_lines():
                if line:
                    try:
                        decoded_line = line.decode("utf-8").strip()
                        if decoded_line.startswith("data: "):
                            data_str = decoded_line[len("data: "):].strip()
                            if data_str == "[DONE]":
                                break
                            data_chunk = json.loads(data_str)
                            content_chunk = data_chunk["choices"][0].get("delta", {}).get("content", "")
                            if content_chunk:
                                print(content_chunk, end="", flush=True)
                                output_text += content_chunk
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        output_text += error_msg
        else:
            err_msg = f"Error: {response.status_code}, {response.text}\n"
            print(err_msg)
            output_text += err_msg
    except Exception as e:
        error_msg = f"[!] > Exception in relationship analysis: {str(e)}\n"
        print(error_msg)
        output_text += error_msg

    log_option(output_text)
    restart()

def read_file_metadata(file_path):
    clear()
    Write.Print(f"🐢 Checking File Data\n {file_path}", Colors.green, interval=0)

    def timeConvert(atime):
        from datetime import datetime
        dt = atime
        newtime = datetime.fromtimestamp(dt)
        return newtime.date()

    def sizeFormat(size):
        newsize = format(size/1024, ".2f")
        return newsize + " KB"

    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} does not exist.")
        Dfile = os.stat(file_path)
        file_size = sizeFormat(Dfile.st_size)
        file_name = os.path.basename(file_path)

        max_length = 60
        file_creation_time = datetime.fromtimestamp(getattr(Dfile, 'st_birthtime', Dfile.st_ctime)).date()
        file_modification_time = timeConvert(Dfile.st_mtime)
        file_last_Access_Date = timeConvert(Dfile.st_atime)

        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)

        metaData_extra = []

        def get_permission_string(file_mode):
            permissions = [
                stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR,
                stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP,
                stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH
            ]
            labels = ['Owner', 'Group', 'Other']
            permission_descriptions = []
            for i, label in enumerate(labels):
                read = 'Yes' if file_mode & permissions[i * 3] else 'No'
                write = 'Yes' if file_mode & permissions[i * 3 + 1] else 'No'
                execute = 'Yes' if file_mode & permissions[i * 3 + 2] else 'No'
                description = f"{label} {{Read: {read}, Write: {write}, Execute: {execute}}}"
                permission_descriptions.append(description)
            return ', '.join(permission_descriptions)

        def gps_extract(exif_dict):
            gps_metadata = exif_dict['GPSInfo']
            lat_ref_num = 1 if gps_metadata['GPSLatitudeRef'] == 'N' else -1
            long_ref_num = 1 if gps_metadata['GPSLongitudeRef'] == 'E' else -1

            lat_list = [float(num) for num in gps_metadata['GPSLatitude']]
            long_list = [float(num) for num in gps_metadata['GPSLongitude']]

            lat_coordinate = (lat_list[0] + lat_list[1]/60 + lat_list[2]/3600) * lat_ref_num
            long_coordinate = (long_list[0] + long_list[1]/60 + long_list[2]/3600) * long_ref_num
            return (lat_coordinate, long_coordinate)

        permissions = get_permission_string(Dfile.st_mode)

        if file_type.startswith("image"):
            with Image.open(file_path) as img:
                metaData_extra.append(f"|{' '*32}Image MetaData{' '*32}|")
                metaData_extra.append(f"|{'-'*78}|")
                info_dict = {
                    "Filename": img.filename,
                    "Image Size": img.size,
                    "Image Height": img.height,
                    "Image Width": img.width,
                    "Image Format": img.format,
                    "Image Mode": img.mode
                }
                for label,value in info_dict.items():
                    metaData_extra.append(f"|  {str(label):<10}: ||  {str(value)[:max_length]:<60}|")
                if img.format == 'TIFF':
                    for tag_id, value in img.tag_v2.items():
                        tag_name = TAGS.get(tag_id, tag_id)
                        metaData_extra.append(f"|  {str(tag_name):<10}: ||  {str(value)[:max_length]:<60}|")
                elif file_path.endswith('.png'):
                    for key, value in img.info.items():
                        metaData_extra.append(f"|  {str(key):<10}: ||  {str(value)[:max_length]:<60}|")
                else:
                    imdata = img._getexif()
                    if imdata:
                        for tag_id in imdata:
                            tag = TAGS.get(tag_id, tag_id)
                            data = imdata.get(tag_id)
                            if tag == "GPSInfo":
                                gps = gps_extract(imdata)
                                metaData_extra.append(f"|  GPS Coordinates: ||  {gps}  |")
                                continue
                            if isinstance(data, bytes):
                                try:
                                    data = data.decode('utf-8', errors='ignore')
                                except UnicodeDecodeError:
                                    data = '<Unintelligible Data>'
                            metaData_extra.append(f"|  {str(tag):<10}: ||  {str(data)[:max_length]:<60}|")
                    else:
                        metaData_extra.append("No EXIF data found.")
        elif file_type == "application/pdf":
            with open(file_path, "rb") as pdf_file:
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                pdf_data = pdf_reader.metadata
                metaData_extra.append(f"|{' '*32}PDF Metadata{' '*32}|")
                metaData_extra.append(f"|{'-'*78}|")
                if pdf_data:
                    for key, value in pdf_data.items():
                        metaData_extra.append(f"|  {str(key):<10}:  || {str(value)[:max_length]:<60}|")
                    if pdf_reader.is_encrypted:
                        metaData_extra.append(f"|  Encrypted: || Yes      |")
                    else:
                        metaData_extra.append(f"|  Encrypted: || No      |")
                else:
                    metaData_extra.append("No PDF metadata found.")
        elif file_path.endswith(('.doc', '.docx')):
            doc = docx.Document(file_path)
            core_properties = doc.core_properties
            doc_metadata = f"""
|{' '*32}Document Properties{' '*32}
|{'='*78}|
| Title:            || {str(core_properties.title) :<60}           |
| Author:           || {str(core_properties.author) :<60}          |
| Subject:          || {str(core_properties.subject) :<60}         |
| Keywords:         || {str(core_properties.keywords) :<60}        |
| Last Modified By: || {str(core_properties.last_modified_by) :<60}|
| Created:          || {str(core_properties.created) :<60}         |
| Modified:         || {str(core_properties.modified) :<60}        |
| Category:         || {str(core_properties.category) :<60}        |
| Content Status:   || {str(core_properties.content_status) :<60}  |
| Version:          || {str(core_properties.version) :<60}         |
| Revision:         || {str(core_properties.revision) :<60}        |
| Comments:         || {str(core_properties.comments) :<60}        |
            """
            metaData_extra.append(doc_metadata)
        elif file_path.endswith(('.xlsx', '.xlsm')):
            workbook = openpyxl.load_workbook(file_path, data_only=True)
            properties = workbook.properties
            excel_metadata = f"""
|{' '*32}Excel Document Properties{' '*32}|
|{'='*78}|
| Title:            || {str(properties.title) :<60}         |
| Author:           || {str(properties.creator) :<60}       |
| Keywords:         || {str(properties.keywords) :<60}      |
| Last Modified By: || {str(properties.lastModifiedBy) :<60}|
| Created:          || {str(properties.created) :<60}       |
| Modified:         || {str(properties.modified) :<60}      |
| Category:         || {str(properties.category) :<60}      |
| Description:      || {str(properties.description) :<60}   |
            """
            metaData_extra.append(excel_metadata)
        elif file_path.endswith(('.pptx', '.pptm')):
            try:
                presentation = Presentation(file_path)
                core_properties = presentation.core_properties
                pptx_metadata = f"""
|{' '*32}PowerPoint Document Properties{' '*31}|
|{'='*78}|
| Title:            || {str(core_properties.title) :<60}           |
| Author:           || {str(core_properties.author) :<60}          |
| Keywords:         || {str(core_properties.keywords) :<60}        |
| Last Modified By: || {str(core_properties.last_modified_by) :<60}|
| Created:          || {str(core_properties.created) :<60}         |
| Modified:         || {str(core_properties.modified) :<60}        |
| Category:         || {str(core_properties.category) :<60}        |
| Description:      || {str(core_properties.subject) :<60}         |
                """
                metaData_extra.append(pptx_metadata)
            except Exception as e:
                metaData_extra.append(f"[Error] Could not read PowerPoint metadata: {e}")
        elif file_type.startswith("audio"):
            try:
                metaData_extra.append(f"|{' '*32}Audio MetaData{' '*32}|\n|{'-'*78}|")
                tinytim = TinyTag.get(file_path)
                if tinytim:
                    metaData_extra.append(f"|  Title:    || {str(tinytim.title)[:max_length]:<60}      |")
                    metaData_extra.append(f"|  Artist:   || {str(tinytim.artist)[:max_length]:<60}     |")
                    metaData_extra.append(f"|  Genre:    || {str(tinytim.genre)[:max_length]:<60}      |")
                    metaData_extra.append(f"|  Album:    || {str(tinytim.album)[:max_length]:<60}      |")
                    metaData_extra.append(f"|  Year:     || {str(tinytim.year)[:max_length]:<60}       |")
                    metaData_extra.append(f"|  Composer: || {str(tinytim.composer)[:max_length]:<60}   |")
                    metaData_extra.append(f"|  A-Artist: || {str(tinytim.albumartist)[:max_length]:<60}|")
                    metaData_extra.append(f"|  Track     || {str(tinytim.track_total)[:max_length]:<60}|")
                    metaData_extra.append(f"|  Duration: || {f'{tinytim.duration:.2f} seconds':<60}    |")
                    metaData_extra.append(f"|  Bitrate:  || {str(tinytim.bitrate) + ' kbps':<60}       |")
                    metaData_extra.append(f"|  Samplrate:|| {str(tinytim.samplerate) + ' Hz':<60}      |")
                    metaData_extra.append(f"|  Channels: || {str(tinytim.channels):<60}                |")

                if file_path.endswith('.mp3'):
                    audio = MP3(file_path, ID3=ID3)
                elif file_path.endswith('.wav'):
                    audio = wave.open(file_path, 'rb')
                elif file_path.endswith('.flac'):
                    audio = FLAC(file_path)
                elif file_path.endswith('.ogg'):
                    audio = OggVorbis(file_path)
                elif file_path.endswith(('.m4a', '.mp4')):
                    audio = MP4(file_path)
                else:
                    audio = None

                if audio is None:
                    metaData_extra.append("Cant Read Audio File for metadata.\n Unsupported")
                else:
                    if hasattr(audio, 'items') and audio.items():
                        for tag, value in audio.items():
                            metaData_extra.append(f"|  {str(tag):<10}: ||  {str(value)[:max_length]:<60}|")
            except Exception as e:
                metaData_extra.append(f"Error processing file: {str(e)}")

        clear()
        metadata_summary = f"""
|{' '*32}File Metadata{' '*33}|
|{'='*78}|
|  File Path:   || {file_path:<60}                  |
|  File Name:   || {file_name:<60}                  |
|  File Size:   || {file_size:<60}                  |
|  File Type:   || {file_type:<60}                  |
|  Permission:  || {permissions:<60}                |
|  Created:     || {str(file_creation_time):<60}    |
|  Modified:    || {str(file_modification_time):<60}|
|  Last Access: || {str(file_last_Access_Date):60}  |
"""
        metadata_summary += "\n".join(metaData_extra)
        metadata_summary += "\n" + "="*78 + "\n"
        Write.Print(metadata_summary, Colors.white, interval=0)
        log_option(metadata_summary)

        print("[?] Export file metadata to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({
                "file_path": file_path,
                "file_name": file_name,
                "file_size": file_size,
                "file_type": file_type,
                "permissions": permissions,
                "created": str(file_creation_time),
                "modified": str(file_modification_time),
                "last_access": str(file_last_Access_Date),
                "additional_metadata": metaData_extra
            }, filename_prefix="file_metadata")

    except Exception as e:
        err_msg = f" ☠️ Error reading file metadata: {str(e)}"
        Write.Print(err_msg, Colors.red, interval=0)
        log_option(err_msg)
    restart()

def hunter_domain_search():
    clear()
    Write.Print("[!] > Hunter.io Domain Search\n", default_color, interval=0)
    domain = Write.Input("[?] > Enter a domain to search via Hunter.io: ", default_color, interval=0).strip()
    if not domain:
        Write.Print("[!] > No domain provided.\n", Colors.red, interval=0)
        restart()
        return
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key=INSERT API KEY HERE"
    output_text = ""
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        lines = [f"[+] Hunter.io Domain Search results for {domain}:"]
        if isinstance(data, dict):
            for k, v in data.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("No structured domain data available.")
        output_text = "\n".join(lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def hunter_email_finder():
    clear()
    Write.Print("[!] > Hunter.io Email Finder\n", default_color, interval=0)
    domain = Write.Input("[?] > Enter a domain (e.g. reddit.com): ", default_color, interval=0).strip()
    first_name = Write.Input("[?] > First Name: ", default_color, interval=0).strip()
    last_name = Write.Input("[?] > Last Name: ", default_color, interval=0).strip()
    if not domain or not first_name or not last_name:
        Write.Print("[!] > Missing domain or names.\n", Colors.red, interval=0)
        restart()
        return
    url = f"https://api.hunter.io/v2/email-finder?domain={domain}&first_name={first_name}&last_name={last_name}&api_key=INSERT API KEY HERE"
    output_text = ""
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        lines = [f"[+] Hunter.io Email Finder results for {first_name} {last_name} @ {domain}:"]
        if isinstance(data, dict):
            for k, v in data.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("No structured email finder data available.")
        output_text = "\n".join(lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def hunter_email_verifier():
    clear()
    Write.Print("[!] > Hunter.io Email Verification\n", default_color, interval=0)
    email = Write.Input("[?] > Enter an email to verify: ", default_color, interval=0).strip()
    if not email:
        Write.Print("[!] > No email provided.\n", Colors.red, interval=0)
        restart()
        return
    url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key=INSERT API KEY HERE"
    output_text = ""
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        lines = [f"[+] Hunter.io Email Verification results for {email}:"]
        if isinstance(data, dict):
            for k, v in data.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("No structured verifier data available.")
        output_text = "\n".join(lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def hunter_company_enrichment():
    clear()
    Write.Print("[!] > Hunter.io Company Enrichment\n", default_color, interval=0)
    domain = Write.Input("[?] > Enter a domain for enrichment (e.g. stripe.com): ", default_color, interval=0).strip()
    if not domain:
        Write.Print("[!] > No domain provided.\n", Colors.red, interval=0)
        restart()
        return
    url = f"https://api.hunter.io/v2/companies/find?domain={domain}&api_key=INSERT API KEY HERE"
    output_text = ""
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        lines = [f"[+] Hunter.io Company Enrichment results for {domain}:"]
        if isinstance(data, dict):
            for k, v in data.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("No structured company data available.")
        output_text = "\n".join(lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def hunter_person_enrichment():
    clear()
    Write.Print("[!] > Hunter.io Person Enrichment\n", default_color, interval=0)
    email = Write.Input("[?] > Enter an email for person enrichment: ", default_color, interval=0).strip()
    if not email:
        Write.Print("[!] > No email provided.\n", Colors.red, interval=0)
        restart()
        return
    url = f"https://api.hunter.io/v2/people/find?email={email}&api_key=INSERT API KEY HERE"
    output_text = ""
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        lines = [f"[+] Hunter.io Person Enrichment results for {email}:"]
        if isinstance(data, dict):
            for k, v in data.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("No structured person data available.")
        output_text = "\n".join(lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def hunter_combined_enrichment():
    clear()
    Write.Print("[!] > Hunter.io Combined Enrichment\n", default_color, interval=0)
    email = Write.Input("[?] > Enter an email for combined enrichment: ", default_color, interval=0).strip()
    if not email:
        Write.Print("[!] > No email provided.\n", Colors.red, interval=0)
        restart()
        return
    url = f"https://api.hunter.io/v2/combined/find?email={email}&api_key=INSERT API KEY HERE"
    output_text = ""
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        lines = [f"[+] Hunter.io Combined Enrichment results for {email}:"]
        if isinstance(data, dict):
            for k, v in data.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("No structured combined data available.")
        output_text = "\n".join(lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def castrick_email_search():
    clear()
    Write.Print("[!] > CastrickClues Email Search\n", default_color, interval=0)
    email = Write.Input("[?] > Enter an email to check via CastrickClues: ", default_color, interval=0).strip()
    if not email:
        Write.Print("[!] > No email provided.\n", Colors.red, interval=0)
        restart()
        return
    type_ = "email"
    query = email
    api_key = "INSERT API KEY HERE"
    headers = {"api-key": api_key}
    url = f"https://api.castrickclues.com/api/v1/search?query={query}&type={type_}"

    def tableify(obj, indent=0):
        lines = []
        prefix = " " * indent
        if isinstance(obj, dict):
            for key, value in obj.items():
                row_title = f"{prefix}{key}:"
                if isinstance(value, (dict, list)):
                    lines.append(f"| {row_title:<76}|")
                    lines.extend(tableify(value, indent + 2))
                else:
                    lines.append(format_table_row(row_title, str(value), indent))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                row_title = f"{prefix}[{idx}]:"
                if isinstance(item, (dict, list)):
                    lines.append(f"| {row_title:<76}|")
                    lines.extend(tableify(item, indent + 2))
                else:
                    lines.append(format_table_row(row_title, str(item), indent))
        else:
            lines.append(format_table_row(prefix.strip(), str(obj), indent))
        return lines

    def format_table_row(label, value, indent):
        row_lines = []
        max_inner_width = 78 - len(label) - 2
        words = value.split()
        current_line = ""
        label_prefix = f"{label} "
        for w in words:
            if len(current_line) + len(w) + 1 <= max_inner_width:
                if current_line:
                    current_line += " " + w
                else:
                    current_line = w
            else:
                row_lines.append(current_line)
                current_line = w
        if current_line:
            row_lines.append(current_line)
        lines_out = []
        if not row_lines:
            lines_out.append(f"| {label_prefix:<78}|")
        else:
            first_line = row_lines[0]
            lines_out.append(f"| {label_prefix + first_line:<78}|")
            for extra_line in row_lines[1:]:
                lines_out.append(f"| {' ' * (len(label_prefix))}{extra_line:<{78-len(label_prefix)}}|")
        return "\n".join(lines_out)

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        clear()
        lines = []
        lines.append(f"╭─{' '*78}─╮")
        lines.append(f"|{' '*30}Castrick Email Search{' '*30}|")
        lines.append(f"|{'='*80}|")
        lines.append(f"| Email Queried: {email:<63}|")
        lines.append(f"|{'-'*80}|")

        if not isinstance(data, (dict, list)):
            data = {"data": data}
        table_lines = tableify(data)
        if not table_lines:
            lines.append("| No structured data returned from Castrick.|")
        else:
            lines.extend(table_lines)
        lines.append(f"╰─{' '*78}─╯")
        output_text = "\n".join(lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def virustotal_domain_report():
    clear()
    domain = Write.Input("[?] > Enter domain for VirusTotal report: ", default_color, interval=0).strip()
    if not domain:
        clear()
        Write.Print("[!] > No domain provided.\n", default_color, interval=0)
        restart()
        return
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": "INSERT API KEY HERE"
    }
    try:
        response = requests.get(url, headers=headers, timeout=60)
        if response.status_code == 200:
            data = response.json()
            formatted_data = json.dumps(data, indent=2)
            output_text = f"[+] VirusTotal Domain Report for {domain}:\n{formatted_data}"
            Write.Print(output_text, Colors.white, interval=0)
        else:
            output_text = f"[!] > Error: HTTP {response.status_code} - {response.text}"
            Write.Print(output_text, Colors.red, interval=0)
    except Exception as e:
        output_text = f"[!] > Exception: {str(e)}"
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def malice_search():
    clear()
    Write.Print("[!] > Enter text to analyze for potential malicious intent:\n", default_color, interval=0)
    malicious_text = Write.Input("[?] > ", default_color, interval=0).strip()
    if not malicious_text:
        clear()
        Write.Print("[!] > No text provided.\n", Colors.red, interval=0)
        restart()
        return

    base_prompt = (
        "You are a malicious-content analyst.\n\n"
        "Task: inspect the supplied text for phishing, scams, or social-engineering cues.\n"
        "Focus indicators: urgency, credential/payment requests, impersonation, unrealistic rewards, "
        "emotional manipulation, suspicious links, grammatical anomalies.\n\n"
        "Output (structured):\n"
        "• Risk level: Low / Medium / High\n"
        "• Bullet-listed red flags, each with a one-sentence rationale\n"
        "• Brief recommendation (e.g., ignore, verify source, report)\n\n"
        "Classify conservatively; if evidence is weak, say so. Flag any urgent security concerns."
    )

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": f"Analyze the following text for potential malicious intent:\n\n{malicious_text}"}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True
    }

    result_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, stream=True, timeout=60)
        if response.status_code == 200:
            for line in response.iter_lines():
                if line:
                    try:
                        decoded_line = line.decode("utf-8").strip()
                        if decoded_line.startswith("data: "):
                            data_str = decoded_line[len("data: "):].strip()
                            if data_str == "[DONE]":
                                break
                            data_chunk = json.loads(data_str)
                            content_chunk = data_chunk["choices"][0].get("delta", {}).get("content", "")
                            if content_chunk:
                                print(content_chunk, end="", flush=True)
                                result_text += content_chunk
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        result_text += error_msg
        else:
            result_text = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
            print(result_text)
    except Exception as e:
        result_text = f"[!] > Error: {str(e)}\n"
        print(result_text)


    clear()
    malice_output = f"""
╭─{' ' * 78}─╮
|{' ' * 28}Malice Search Analysis{' ' * 28}|
|{'=' * 80}|
| [+] > Input Text: {malicious_text[:60]:<60}|
|{'-' * 80}|
{result_text}
╰─{' ' * 78}─╯
"""
    Write.Print(malice_output, Colors.white, interval=0)
    log_option(malice_output)
    restart()

def supply_vendor_search():
    clear()
    Write.Print("[!] > Supply/Vendor Risk Assessment\n", default_color, interval=0)
    company_name = Write.Input("[?] > Enter Company Name: ", default_color, interval=0).strip()
    start_date = Write.Input("[?] > Enter Start Date (YYYY-MM-DD): ", default_color, interval=0).strip()
    if not company_name or not start_date:
        clear()
        Write.Print("[!] > Company name and start date are required.\n", Colors.red, interval=0)
        restart()
        return

    base_prompt = (
        "Please provide a comprehensive risk assessment for " + company_name +
        " covering the period from " + start_date + " to present. Include any documented incidents, regulatory violations, compliance issues, legal proceedings, and public controversies. "
        "Focus on areas that could impact business continuity, reputation, or contractual obligations, including but not limited to: data breaches, cybersecurity incidents, environmental violations, labor disputes, financial irregularities, supply chain disruptions, product quality issues, and regulatory non-compliance. "
        "Detail the nature of each incident, its resolution status, any penalties or settlements imposed, and implemented remediation measures. Additionally, highlight any patterns of recurring issues or systemic problems. You must cite all sources in Chicago format."
    )
    
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": f"Supply/Vendor Risk Assessment for {company_name} from {start_date} to present."}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True 
    }
    
    result_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, stream=True, timeout=60)
        if response.status_code == 200:
            for line in response.iter_lines():
                if line:
                    try:
                        decoded_line = line.decode("utf-8").strip()
                        if decoded_line.startswith("data: "):
                            data_str = decoded_line[len("data: "):].strip()
                            if data_str == "[DONE]":
                                break
                            data_chunk = json.loads(data_str)
                            content_chunk = data_chunk["choices"][0].get("delta", {}).get("content", "")
                            if content_chunk:
                                print(content_chunk, end="", flush=True)
                                result_text += content_chunk
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        result_text += error_msg
        else:
            result_text = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
            print(result_text)
    except Exception as e:
        result_text = f"[!] > Error: {str(e)}\n"
        print(result_text)
    
    clear()
    output_text = f"""
╭─{' ' * 78}─╮
|{' ' * 26}Supply/Vendor Risk Assessment{' ' * 26}|
|{'=' * 80}|
| [+] > Company: {company_name:<62}|
| [+] > Period:  {start_date} to present{' ' * (62 - len(start_date) - len(" to present"))}|
|{'-' * 80}|
{result_text}
╰─{' ' * 78}─╯
"""
    Write.Print(output_text, Colors.white, interval=0)
    log_option(output_text)
    restart()

def wayback_lookup(domain):
    clear()
    if not domain:
        Write.Print("[!] No domain provided for Wayback lookup.\n", Colors.red, interval=0)
        restart()
        return
    base_url = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": domain,
        "output": "json",
        "fl": "original,timestamp",
        "collapse": "digest",
        "filter": "statuscode:200",
        "limit": 20
    }
    try:
        resp = requests.get(base_url, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        if len(data) <= 1:
            Write.Print("[!] > No historical snapshots found (or none with status 200).\n", Colors.red, interval=0)
            restart()
            return

        snapshots = data[1:]
        output_text = f"\nWayback Machine Snapshots for {domain}:\n"
        for snap in snapshots:
            original_url, timestamp = snap
            archive_url = f"https://web.archive.org/web/{timestamp}/{original_url}"
            output_text += f"- {timestamp} -> {archive_url}\n"

        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)

        print("[?] Export Wayback data to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({"domain": domain, "snapshots": snapshots}, filename_prefix="wayback_lookup")
    except Exception as e:
        Write.Print(f"[!] > Error fetching Wayback Machine data: {str(e)}\n", Colors.red, interval=0)
    restart()

def basic_port_scan(target, ports=[20, 21, 22, 80, 443, 8080, 23, 25, 53, 67, 68, 69, 88, 110, 123, 137, 138, 139, 143, 162, 162, 389, 427, 445, 465, 500, 636, 993, 995, 1433, 1434, 3306, 5060, 5061]):
    clear()
    Write.Print(f"[!] >Port Scan for {target}\n", default_color, interval=0)
    result_lines = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                result_lines.append(f"Port {port} is OPEN.")
            else:
                result_lines.append(f"Port {port} is closed or filtered.")
        except Exception as e:
            result_lines.append(f"Port {port} -> Error: {str(e)}")
        finally:
            sock.close()

    report = f"\nPort Scan Results for {target}:\n" + "\n".join(result_lines)
    Write.Print(report, Colors.white, interval=0)
    log_option(report)

    print("[?] Export port scan results to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"target": target, "scan_results": result_lines}, filename_prefix="port_scan")
    restart()

def bulk_domain_processing(csv_path):
    clear()
    if not os.path.isfile(csv_path):
        Write.Print("[!] CSV file not found or invalid path.\n", Colors.red, interval=0)
        restart()
        return

    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            lines = [x.strip() for x in f if x.strip()]
    except UnicodeDecodeError:
        with open(csv_path, "r", encoding="latin-1") as f:
            lines = [x.strip() for x in f if x.strip()]

    Write.Print(f"[!] Found {len(lines)} entries in {csv_path}.\n", default_color, interval=0)
    Write.Print("Choose the checks you want to run on each domain/IP:\n", Colors.white, interval=0)
    Write.Print("[1] DNS Lookup\n[2] WHOIS Lookup\n[3] Subdomain Enumeration\n[4] IP Info (if IP)\n[5] SSL Cert Info (if domain)\n\n", Colors.white, interval=0)
    chosen = Write.Input("[?] Enter your choices separated by commas (e.g. 1,2,3): ", default_color, interval=0).strip()
    chosen_set = set(x.strip() for x in chosen.split(","))

    results = {}
    for entry in lines:
        out_lines = [f"Results for {entry}:"]
        if "1" in chosen_set:
            try:
                out_lines.append("DNS Lookup:")
                try:
                    answers = dns.resolver.resolve(entry, 'A')
                    out_lines.append(f"A Records: {[str(a) for a in answers]}")
                except:
                    out_lines.append("No A records / Error retrieving.")
            except Exception as e:
                out_lines.append(f"DNS Lookup Error: {str(e)}")
        if "2" in chosen_set:
            try:
                w = whois.whois(entry)
                out_lines.append(f"WHOIS: {w.domain_name}, Registrar: {w.registrar}")
            except Exception as e:
                out_lines.append(f"WHOIS Error: {str(e)}")
        if "3" in chosen_set and validate_domain_input(entry):
            try:
                out_lines.append("Subdomain Enumeration: See script logs for details.")
            except Exception as e:
                out_lines.append(f"Subdomain enumeration error: {str(e)}")
        if "4" in chosen_set:
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', entry):
                details = get_ip_details(entry)
                if details:
                    out_lines.append(f"IP Info: City={details.get('city','N/A')} Region={details.get('region','N/A')} Org={details.get('org','N/A')}")
                else:
                    out_lines.append("IP Info not available.")
            else:
                out_lines.append("Not an IP, skipping IP Info.")
        if "5" in chosen_set and validate_domain_input(entry):
            try:
                context = ssl.create_default_context()
                with socket.create_connection((entry, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=entry) as ssock:
                        cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                out_lines.append(f"SSL Issued To: {subject.get('commonName','N/A')}, By: {issuer.get('commonName','N/A')}")
            except Exception as e:
                out_lines.append(f"SSL Error: {str(e)}")

        results[entry] = "\n".join(out_lines)

    for entry, data in results.items():
        Write.Print("\n" + data + "\n", Colors.white, interval=0)

    print("[?] Export bulk domain results to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json(results, filename_prefix="bulk_domain")
    restart()

def phone_leak_search():
    clear()
    Write.Print("[!] > Phone Leak Search\n", Colors.white, interval=0)
    phone_number = Write.Input("[?] > Enter the phone number to check for leaks: ", Colors.white, interval=0).strip()
    if not phone_number:
        Write.Print("[!] > No phone number provided.\n", Colors.red, interval=0)
        restart()
        return

    conn = http.client.HTTPSConnection("phone-leak-search.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "phone-leak-search.p.rapidapi.com"
    }
    conn.request("GET", f"/api/search?phone={phone_number}", headers=headers)
    res = conn.getresponse()
    data = res.read()

    Write.Print(data.decode("utf-8"), Colors.white, interval=0)
    log_option(data.decode("utf-8"))

    print("[?] Export phone leak search to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"phone_number": phone_number, "results": data.decode("utf-8")}, filename_prefix="phone_leak_search")
    restart()

def aes_encrypt():
    clear()
    Write.Print("[!] > AES Encryption\n", Colors.white, interval=0)
    plaintext = Write.Input("[?] > Enter the plaintext to encrypt: ", Colors.white, interval=0).strip()
    encryption_key = Write.Input("[?] > Enter the encryption key: ", Colors.white, interval=0).strip()

    if not plaintext or not encryption_key:
        Write.Print("[!] > Plaintext and encryption key are required.\n", Colors.red, interval=0)
        restart()
        return

    conn = http.client.HTTPSConnection("encryption-api2.p.rapidapi.com")
    payload = json.dumps({"text": plaintext, "encryption_key": encryption_key})
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "encryption-api2.p.rapidapi.com",
        'Content-Type': "application/json"
    }
    conn.request("POST", "/enc.php", payload, headers)

    res = conn.getresponse()
    data = res.read()

    if res.status != 200:
        Write.Print(f"[!] > Error: Received status code {res.status}\n", Colors.red, interval=0)
        restart()
        return

    try:
        response_data = json.loads(data.decode("utf-8"))
        clear()
        output_text = "[+] Encryption Results:\n"
        output_text += f"- Ciphertext: {response_data.get('ciphertext', 'N/A')}\n"
        output_text += f"- IV: {response_data.get('iv', 'N/A')}\n"

        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)

        print("[?] Export encryption results to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({"plaintext": plaintext, "encryption_key": encryption_key, "results": response_data}, filename_prefix="aes_encrypt")

    except json.JSONDecodeError:
        Write.Print("[!] > Error: Failed to decode JSON response.\n", Colors.red, interval=0)
    except Exception as e:
        Write.Print(f"[!] > An error occurred: {str(e)}\n", Colors.red, interval=0)
    restart()

def aes_decrypt():
    clear()
    Write.Print("[!] > AES Decryption\n", Colors.white, interval=0)
    ciphertext = Write.Input("[?] > Enter the ciphertext to decrypt: ", Colors.white, interval=0).strip()
    encryption_key = Write.Input("[?] > Enter the encryption key to decrypt: ", Colors.white, interval=0).strip()
    iv = Write.Input("[?] > Enter the Initialization Vector to decrypt: ", Colors.white, interval=0).strip()

    if not ciphertext or not encryption_key or not iv:
        Write.Print("[!] > Ciphertext, encryption key, and IV are required.\n", Colors.red, interval=0)
        restart()
        return

    conn = http.client.HTTPSConnection("encryption-api2.p.rapidapi.com")
    payload = json.dumps({"ciphertext": ciphertext, "encryption_key": encryption_key, "iv": iv})
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "encryption-api2.p.rapidapi.com",
        'Content-Type': "application/json"
    }
    conn.request("POST", "/dec.php", payload, headers)

    res = conn.getresponse()
    data = res.read()

    if res.status != 200:
        Write.Print(f"[!] > Error: Received status code {res.status}\n", Colors.red, interval=0)
        restart()
        return

    try:
        response_data = json.loads(data.decode("utf-8"))
        clear()
        output_text = "[+] Decryption Results:\n"
        output_text += f"- Plaintext: {response_data.get('plaintext', 'N/A')}\n"
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
        print("[?] Export decryption results to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({"ciphertext": ciphertext, "encryption_key": encryption_key, "iv": iv, "results": response_data}, filename_prefix="aes_decrypt")
    except json.JSONDecodeError:
        Write.Print("[!] > Error: Failed to decode JSON response.\n", Colors.red, interval=0)
    except Exception as e:
        Write.Print(f"[!] > An error occurred: {str(e)}\n", Colors.red, interval=0)
    restart()

def malicious_scan():
    clear()
    Write.Print("[!] > Malicious/Scam URL Analysis\n", default_color, interval=0)

    conn = http.client.HTTPSConnection("malicious-scanner.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "malicious-scanner.p.rapidapi.com"
    }
    url = "https%3A%2F%2Fvryjm.page.link%2FjS6a"  
    conn.request("GET", f"/rapid/url?url={url}", headers=headers)

    res = conn.getresponse()
    data = res.read()
    output_text = data.decode("utf-8")

    Write.Print(output_text, Colors.white, interval=0)
    log_option(output_text)
    restart()

def email_intelligence_check():
    clear()
    Write.Print("[!] > Email Intelligence Search\n", default_color, interval=0)
    email = Write.Input("[?] > Enter the email address to search: ", default_color, interval=0).strip()
    if not email:
        Write.Print("[!] > Please enter an email address.\n", default_color, interval=0)
        return

    encoded_email = urllib.parse.quote(email)
    conn = http.client.HTTPSConnection("email-intelligence-api.p.rapidapi.com")
    headers = {
        "x-rapidapi-key": "INSERT API KEY HERE",
        "x-rapidapi-host": "email-intelligence-api.p.rapidapi.com",
    }
    conn.request("GET", f"/v1/check?email={encoded_email}", headers=headers)
    res = conn.getresponse()

    if res.status != 200:
        Write.Print(f"[!] > Error: Received status code {res.status}.\n", Colors.red, interval=0)
        restart()
        return

    response_text = res.read().decode("utf-8")
    try:
        parsed_data = json.loads(response_text)
    except json.JSONDecodeError:
        Write.Print("[!] > Failed to decode JSON response.\n", Colors.red, interval=0)
        restart()
        return

    Write.Print("\n[+] > Email Intelligence Result\n", Colors.green, interval=0)
    for key, value in parsed_data.items():
        if isinstance(value, dict):
            Write.Print(f"\n{key.upper()}:\n", Colors.cyan, interval=0)
            for sub_key, sub_val in value.items():
                Write.Print(f"    {sub_key:<20}: {sub_val}\n", Colors.white, interval=0)
        else:
            Write.Print(f"{key:<20}: {value}\n", Colors.white, interval=0)

    formatted_json = json.dumps(parsed_data, indent=4, ensure_ascii=False)
    log_option(formatted_json)

    Write.Print("\nPress Enter to return to the main menu...", Colors.white, interval=0)
    Write.Input("", Colors.white, interval=0)
    restart()

import http.client, json
from urllib.parse import quote

def fetch_tiktok_data():
    username = input("Enter the TikTok username: ").strip()
    if not username:
        Write.Print("[!] Error: TikTok username must be provided.", Colors.red, interval=0)
        restart() 
        return

    conn = http.client.HTTPSConnection("tiktok-private1.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "tiktok-private1.p.rapidapi.com"
    }
    endpoint = f"/user?username={username}"
    conn.request("GET", endpoint, headers=headers)
    res = conn.getresponse()
    if res.status == 200:
        data = res.read()
        output_text = data.decode("utf-8")
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
    else:
        Write.Print(f"[!] Error: Received status code {res.status}.", Colors.red, interval=0)
    restart()

def fetch_identity_data():
    clear()
    Write.Print("[!] > Fake Identity Generator\n", default_color, interval=0)

    conn = http.client.HTTPSConnection("fake-identity-generation.p.rapidapi.com")
    headers = {
        "x-rapidapi-key": "INSERT API KEY HERE",
        "x-rapidapi-host": "fake-identity-generation.p.rapidapi.com",
    }
    conn.request("GET", "/identity/person/address", headers=headers)
    res = conn.getresponse()

    if res.status != 200:
        Write.Print(f"[!] > Error: Received status code {res.status}.\n", Colors.red, interval=0)
        restart()
        return

    response_text = res.read().decode("utf-8")
    try:
        parsed_data = json.loads(response_text)
    except json.JSONDecodeError:
        Write.Print("[!] > Failed to decode JSON response.\n", Colors.red, interval=0)
        restart()
        return

    def print_structured(obj, level=0):
        indent = "    " * level
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    Write.Print(f"{indent}{k}:\n", Colors.cyan, interval=0)
                    print_structured(v, level + 1)
                else:
                    Write.Print(f"{indent}{k:<20}: {v}\n", Colors.white, interval=0)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj, 1):
                if isinstance(item, (dict, list)):
                    Write.Print(f"{indent}[{idx}]:\n", Colors.cyan, interval=0)
                    print_structured(item, level + 1)
                else:
                    Write.Print(f"{indent}[{idx}] {item}\n", Colors.white, interval=0)
        else:
            Write.Print(f"{indent}{obj}\n", Colors.white, interval=0)

    Write.Print("\n[+] > Generated Identity\n", Colors.green, interval=0)
    print_structured(parsed_data)

    log_option(json.dumps(parsed_data, indent=4, ensure_ascii=False))

    Write.Print("\nPress Enter to return to the main menu...", Colors.white, interval=0)
    Write.Input("", Colors.white, interval=0)
    restart()
  
import json

def skip_trace_search():
    clear()
    Write.Print("[!] > Skip Trace Search by Name\n", default_color, interval=0)
    name = Write.Input("[?] > Enter the name for the search (e.g., Elon Musk): ", default_color, interval=0).strip()
    if not name:
        Write.Print("[!] > Please enter a valid name.\n", default_color, interval=0)
        return

    encoded_name = quote(name)

    conn = http.client.HTTPSConnection("skip-tracing-working-api.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "skip-tracing-working-api.p.rapidapi.com"
    }
    conn.request("GET", f"/search/byname?name={encoded_name}&page=1", headers=headers)
    res = conn.getresponse()
    if res.status == 200:
        data = res.read()
        try:
            json_data = json.loads(data.decode("utf-8"))
            output_text = json.dumps(json_data, indent=4)  # Pretty-print JSON
            Write.Print(output_text, Colors.white, interval=0)
            log_option(output_text)
        except json.JSONDecodeError:
            Write.Print("[!] Error: Failed to decode JSON response.", Colors.red, interval=0)
            restart()
    else:
        Write.Print(f"[!] Error: Received status code {res.status}.", Colors.red, interval=0)
    restart()

def skip_trace_search_by_id():
    clear()
    Write.Print("[!] Enter the ID for Skip Trace Search:\n", default_color, interval=0)
    peo_id = Write.Input("[?] > Enter the ID: ", default_color, interval=0).strip()
    if not peo_id:
        Write.Print("[!] > No ID provided.\n", Colors.red, interval=0)
        restart()
        return

    conn = http.client.HTTPSConnection("skip-tracing-working-api.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "skip-tracing-working-api.p.rapidapi.com"
    }
    conn.request("GET", f"/search/detailsbyID?peo_id={peo_id}", headers=headers)
    res = conn.getresponse()
    if res.status == 200:
        data = res.read()
        response_data = json.loads(data.decode("utf-8"))
        formatted_output = json.dumps(response_data, indent=2)
        Write.Print(formatted_output, Colors.white, interval=0)
        log_option(formatted_output)
    else:
        Write.Print(f"[!] Error: Received status code {res.status}.", Colors.red, interval=0)
    restart()

def truecaller_search(phone_number):
    conn = http.client.HTTPSConnection("truecaller-data2.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "truecaller-data2.p.rapidapi.com"
    }
    conn.request("GET", f"/search/{phone_number}", headers=headers)
    res = conn.getresponse()
    if res.status == 200:
        data = res.read()
        try:
            output_JSON = json.loads(data.decode("utf-8"))
            formatted_output = json.dumps(output_JSON, indent=4)
            Write.Print(formatted_output, Colors.white, interval=0)
            log_option(formatted_output)
        except json.JSONDecodeError:
            Write.Print("[!] Error: Failed to decode JSON response.", Colors.red, interval=0)
    else:
        Write.Print(f"[!] Error: Received status code {res.status}.", Colors.red, interval=0)
    restart()

def ship_info(mmsi):
    if not mmsi:
        clear()
        Write.Print("[!] > Please enter a valid MMSI number.\n", default_color, interval=0)
        restart()
        return
    url = f"https://api.facha.dev/v1/ship/{mmsi}"
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        output_text = f"Ship Info for MMSI {mmsi}:\n" + json.dumps(data, indent=2)
        clear()
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
        print("[?] Export ship info to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({"mmsi": mmsi, "data": data}, filename_prefix="ship_info")
    except Exception as e:
        clear()
        Write.Print(f"[!] > Error retrieving ship info: {str(e)}\n", Colors.red, interval=0)
    restart()

def ship_radius(latitude, longitude, radius):

    if not latitude or not longitude or not radius:
        clear()
        Write.Print("[!] > Please enter valid latitude, longitude, and radius values.\n", default_color, interval=0)
        restart()
        return

    url = f"https://api.facha.dev/v1/ship/radius/{latitude}/{longitude}/{radius}"
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        output_text = (
            f"Ships within a radius of {radius} around ({latitude}, {longitude}):\n" 
            + json.dumps(data, indent=2)
        )
        clear()
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
        print("[?] Export ship radius data to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({
                "latitude": latitude,
                "longitude": longitude,
                "radius": radius,
                "data": data
            }, filename_prefix="ship_radius")
    except Exception as e:
        clear()
        Write.Print(f"[!] > Error retrieving ship radius info: {str(e)}\n", Colors.red, interval=0)
    restart()

def aircraft_live_range(lat, lon, range_value):
   
    if not lat or not lon or not range_value:
        clear()
        Write.Print("[!] > Please enter valid latitude, longitude, and range values.\n", default_color, interval=0)
        restart()
        return
    
    url = f"https://api.facha.dev/v1/aircraft/live/range/{lat}/{lon}/{range_value}"
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        output_text = (
            f"Live aircraft within a range of {range_value} around ({lat}, {lon}):\n"
            + json.dumps(data, indent=2)
        )
        clear()
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
        print("[?] Export aircraft live range data to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({
                "latitude": lat,
                "longitude": lon,
                "range": range_value,
                "data": data
            }, filename_prefix="aircraft_live_range")
    except Exception as e:
        clear()
        Write.Print(f"[!] > Error retrieving aircraft live range info: {str(e)}\n", Colors.red, interval=0)
    restart()

def aircraft_live_callsign(callsign):
    if not callsign:
        clear()
        Write.Print("[!] > Please enter a valid callsign.\n", default_color, interval=0)
        restart()
        return
    url = f"https://api.facha.dev/v1/aircraft/live/callsign/{callsign}"
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        output_text = (
            f"Live aircraft info for callsign '{callsign}':\n" +
            json.dumps(data, indent=2)
        )
        clear()
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
        print("[?] Export aircraft callsign data to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({
                "callsign": callsign,
                "data": data
            }, filename_prefix="aircraft_live_callsign")
    except Exception as e:
        clear()
        Write.Print(f"[!] > Error retrieving aircraft info for callsign '{callsign}': {str(e)}\n", Colors.red, interval=0)
    restart()

import requests
import json

def predicta_search():
    clear()
    Write.Print("[!] Predicta Search:\n", default_color, interval=0)

    query = Write.Input("[?] Enter the query (e.g., email or phone number): ", default_color, interval=0).strip()
    if not query:
        Write.Print("[!] Query is required.", Colors.red, interval=0)
        restart()
        return

    query_type = Write.Input("[?] Enter the query type (email/phone): ", default_color, interval=0).strip().lower()
    if query_type not in ["email", "phone"]:
        Write.Print("[!] Invalid query type. Use 'email' or 'phone'.", Colors.red, interval=0)
        restart()
        return

    url = "https://dev.predictasearch.com/api/search"
    api_key = "INSERT API KEY HERE"
    headers = {
        'x-api-key': api_key,
        'Content-Type': 'application/json'
    }

    payload = {
        "query": query,
        "query_type": query_type,
        "networks": ["all"]  
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        if response.status_code == 200:
            data = response.json()
            output_text = json.dumps(data, indent=2)  
            Write.Print(output_text, Colors.white, interval=0)
            log_option(output_text)
        else:
            Write.Print(f"[!] Error: HTTP {response.status_code} - {response.text}", Colors.red, interval=0)
    except Exception as e:
        Write.Print(f"[!] Error: {str(e)}", Colors.red, interval=0)

    restart()

def generate_identity():

    conn = http.client.HTTPSConnection("identity-generator.p.rapidapi.com")

    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "identity-generator.p.rapidapi.com"
    }

    conn.request("GET", "/identitygenerator/api/", headers=headers)

    res = conn.getresponse()
    data = res.read()
    output = data.decode("utf-8")

    print(output)
    restart()

def virtual_phone_numbers_detector():
    import http.client
    import json
    phone = input("Enter the phone number to check (in international format, e.g., +447497265710): ").strip()
    if not phone:
        print("No phone number provided. Exiting function.")
        return
    conn = http.client.HTTPSConnection("virtual-phone-numbers-detector.p.rapidapi.com")
    payload = json.dumps({"phone": phone})
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "virtual-phone-numbers-detector.p.rapidapi.com",
        'Content-Type': "application/json"
    }
    conn.request("POST", "/check-number", payload, headers)
    res = conn.getresponse()
    data = res.read()
    print(data.decode("utf-8"))
    restart()

def mac_address_lookup():
    clear()
    Write.Print("[!] > MAC Address Lookup\n", Colors.white, interval=0)

    mac = Write.Input(
        "[?] > Enter MAC address (e.g., 00-B0-D0-63-C2-26): ",
        Colors.white,
        interval=0
    ).strip()

    if not mac:
        Write.Print("[!] > Please enter a valid MAC address.\n", Colors.red, interval=0)
        restart()
        return

    encoded_mac = urllib.parse.quote(mac)

    conn = http.client.HTTPSConnection("mac-address-lookup-api-apiverve.p.rapidapi.com")
    headers = {
        "x-rapidapi-key": "INSERT API KEY HERE",
        "x-rapidapi-host": "mac-address-lookup-api-apiverve.p.rapidapi.com",
        "Accept": "application/json"
    }
    conn.request("GET", f"/v1/macaddresslookup?mac={encoded_mac}", headers=headers)
    res = conn.getresponse()

    if res.status != 200:
        Write.Print(f"[!] > Error: Received status code {res.status}.\n", Colors.red, interval=0)
        restart()
        return

    data = res.read().decode("utf-8")
    output = json.dumps(json.loads(data), indent=4, ensure_ascii=False)
    Write.Print(output + "\n", Colors.white, interval=0)

    Write.Input("[?] > Press Enter to return to the main menu...", Colors.white, interval=0)
    restart()

def autoscan_ip_info(ip):
    if not ip:
        return "[!] Error: IP address was not provided for IP info lookup.\n"
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=60)
        response.raise_for_status()
        data = response.json()
        loc = data.get('loc', 'N/A')
        maps_link = f"https://www.google.com/maps?q={loc}" if loc != 'N/A' else 'N/A'
        
        result = (
            f"\n╭─{' '*78}─╮\n"
            f"|{' '*34} IP Details {' '*34}|\n"
            f"|{'='*80}|\n"
            f"| [+] > IP Address         || {data.get('ip', 'N/A'):<51}|\n"
            f"| [+] > City               || {data.get('city', 'N/A'):<51}|\n"
            f"| [+] > Region             || {data.get('region', 'N/A'):<51}|\n"
            f"| [+] > Country            || {data.get('country', 'N/A'):<51}|\n"
            f"| [+] > Postal/ZIP Code    || {data.get('postal', 'N/A'):<51}|\n"
            f"| [+] > ISP                || {data.get('org', 'N/A'):<51}|\n"
            f"| [+] > Coordinates        || {loc:<51}|\n"
            f"| [+] > Timezone           || {data.get('timezone', 'N/A'):<51}|\n"
            f"| [+] > Location           || {maps_link:<51}|\n"
            f"╰─{' '*24}─╯╰─{' '*50}─╯\n"
        )
    except Exception as e:
        result = f"[!] Error retrieving IP info for '{ip}': {str(e)}\n"
    return result


def autoscan_deep_account_search(nickname):
    if not nickname:
        return "[!] Error: Username was not provided for Deep Account Search.\n"
    sites = [
        "https://youtube.com/@{target}",
        "https://facebook.com/{target}",
        "https://wikipedia.org/wiki/User:{target}",
        "https://instagram.com/{target}",
        "https://reddit.com/user/{target}",
        "https://medium.com/@{target}",
        "https://www.quora.com/profile/{target}",
        "https://bing.com/{target}",
        "https://x.com/{target}",
        "https://yandex.ru/{target}",
        "https://whatsapp.com/{target}",
        "https://yahoo.com/{target}",
        "https://amazon.com/{target}",
        "https://duckduckgo.com/{target}",
        "https://yahoo.co.jp/{target}",
        "https://tiktok.com/@{target}",
        "https://msn.com/{target}",
        "https://netflix.com/{target}",
        "https://weather.com/{target}",
        "https://live.com/{target}",
        "https://naver.com/{target}",
        "https://microsoft.com/{target}",
        "https://twitch.tv/{target}",
        "https://office.com/{target}",
        "https://vk.com/{target}",
        "https://pinterest.com/{target}",
        "https://discord.com/{target}",
        "https://aliexpress.com/{target}",
        "https://github.com/{target}",
        "https://adobe.com/{target}",
        "https://rakuten.co.jp/{target}",
        "https://ikea.com/{target}",
        "https://bbc.co.uk/{target}",
        "https://amazon.co.jp/{target}",
        "https://speedtest.net/{target}",
        "https://samsung.com/{target}",
        "https://healthline.com/{target}",
        "https://medlineplus.gov/{target}",
        "https://roblox.com/users/{target}/profile",
        "https://cookpad.com/{target}",
        "https://indiatimes.com/{target}",
        "https://mercadolivre.com.br/{target}",
        "https://britannica.com/{target}",
        "https://merriam-webster.com/{target}",
        "https://hurriyet.com.tr/{target}",
        "https://steamcommunity.com/user/{target}",
        "https://booking.com/{target}",
        "https://support.google.com/{target}",
        "https://bbc.com/{target}",
        "https://playstation.com/{target}",
        "https://ebay.com/usr/{target}",
        "https://poki.com/{target}",
        "https://walmart.com/{target}",
        "https://medicalnewstoday.com/{target}",
        "https://gov.uk/{target}",
        "https://nhs.uk/{target}",
        "https://detik.com/{target}",
        "https://cricbuzz.com/{target}",
        "https://nih.gov/{target}",
        "https://uol.com.br/{target}",
        "https://ilovepdf.com/{target}",
        "https://clevelandclinic.org/{target}",
        "https://cnn.com/{target}",
        "https://globo.com/{target}",
        "https://nytimes.com/{target}",
        "https://taboola.com/{target}",
        "https://pornhub.com/users/{target}",
        "https://redtube.com/users/{target}",
        "https://xnxx.com/profiles/{target}",
        "https://brazzers.com/profile/{target}",
        "https://xhamster.com/users/{target}",
        "https://onlyfans.com/{target}",
        "https://xvideos.es/profiles/{target}",
        "https://xvideos.com/profiles/{target}",
        "https://chaturbate.com/{target}",
        "https://redgifs.com/users/{target}",
        "https://tinder.com/{target}",
        "https://pof.com/{target}",
        "https://match.com/{target}",
        "https://eharmony.com/{target}",
        "https://bumble.com/{target}",
        "https://okcupid.com/{target}",
        "https://Badoo.com/{target}",
        "https://dating.com/{target}",
        "https://trello.com/{target}",
        "https://mapquest.com/{target}",
        "https://zoom.com/{target}",
        "https://apple.com/{target}",
        "https://dropbox.com/{target}",
        "https://weibo.com/{target}",
        "https://wordpress.com/{target}",
        "https://cloudflare.com/{target}",
        "https://salesforce.com/{target}",
        "https://fandom.com/{target}",
        "https://paypal.com/{target}",
        "https://soundcloud.com/{target}",
        "https://forbes.com/{target}",
        "https://theguardian.com/{target}",
        "https://hulu.com/{target}",
        "https://stackoverflow.com/users/{target}",
        "https://businessinsider.com/{target}",
        "https://huffpost.com/{target}",
        "https://booking.com/{target}",
        "https://pastebin.com/u/{target}",
        "https://producthunt.com/@{target}",
        "https://pypi.org/user/{target}",
        "https://slideshare.com/{target}",
        "https://strava.com/athletes/{target}",
        "https://tldrlegal.com/{target}",
        "https://t.me/{target}",
        "https://last.fm/user{target}",
        "https://data.typeracer.com/pit/profile?user={target}",
        "https://tryhackme.com/p/{target}",
        "https://trakt.tv/users/{target}",
        "https://scratch.mit.edu/users/{target}",
        "https://replit.com?{target}",
        "https://hackaday.io/{target}",
        "https://freesound.org/people/{target}",
        "https://hub.docker.com/u/{target}",
        "https://disqus.com/{target}",
        "https://www.codecademy.com/profiles/{target}",
        "https://www.chess.com/member/{target}",
        "https://bitbucket.org/{target}",
        "https://www.twitch.tv?{target}",
        "https://wikia.com/wiki/User:{target}",
        "https://steamcommunity.com/groups{target}",
        "https://keybase.io?{target}",
        "http://en.gravatar.com/{target}",
        "https://vk.com/{target}",
        "https://deviantart.com/{target}",
        "https://www.behance.net/{target}",
        "https://vimeo.com/{target}",
        "https://www.youporn.com/user/{target}",
        "https://profiles.wordpress.org/{target}",
        "https://tryhackme.com/p/{target}",
        "https://www.scribd.com/{target}",
        "https://myspace.com/{target}",
        "https://genius.com/{target}",
        "https://genius.com/artists/{target}",
        "https://www.flickr.com/people/{target}",
        "https://www.fandom.com/u/{target}",
        "https://www.chess.com/member/{target}",
        "https://buzzfeed.com/{target}",
        "https://www.buymeacoffee.com/{target}",
        "https://about.me/{target}",
        "https://discussions.apple.com/profile/{target}",
        "https://giphy.com/{target}",
        "https://scholar.harvard.edu/{target}",
        "https://www.instructables.com/member/{target}",
        "http://www.wikidot.com/user:info/{target}",
        "https://erome.com/{target}",
        "https://www.alik.cz/u/{target}",
        "https://rblx.trade/p/{target}",
        "https://www.paypal.com/paypalme/{target}",
        "https://hackaday.io/{target}",
        "https://connect.garmin.com/modern/profile/{target}"
    ]
    urls = [site.format(target=nickname) for site in sites]
    found_accounts = []

    def check_url(url):
        try:
            response = requests.head(url, timeout=10, allow_redirects=True)
            if response.status_code == 200 or response.status_code == 405: 
                return f"[+] {url}"
        except requests.exceptions.RequestException:
            return None 
        return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(check_url, urls))
    
    found_accounts = [res for res in results if res]

    if not found_accounts:
        return f"No accounts found for username '{nickname}' on the checked sites.\n"
        
    result_str = f"Found {len(found_accounts)} potential accounts for '{nickname}':\n"
    result_str += "\n".join(found_accounts) + "\n"
    return result_str


def autoscan_phone_info(phone_number):
    if not phone_number:
        return "[!] Error: Phone number was not provided.\n"
    try:
        parsed_number = phonenumbers.parse(phone_number)
        if not phonenumbers.is_valid_number(parsed_number):
            return f"[!] '{phone_number}' is not a valid phone number.\n"

        country = geocoder.country_name_for_number(parsed_number, "en") or "N/A"
        region = geocoder.description_for_number(parsed_number, "en") or "N/A"
        operator = carrier.name_for_number(parsed_number, "en") or "N/A"
        
        result = (
            f"\n╭─{' '*50}─╮\n"
            f"|{' '*17}Phone Number Info{' '*18}|\n"
            f"|{'='*52}|\n"
            f"| [+] > Number   || {phone_number:<33}|\n"
            f"| [+] > Country  || {country:<33}|\n"
            f"| [+] > Region   || {region:<33}|\n"
            f"| [+] > Operator || {operator:<33}|\n"
            f"| [+] > Validity || Valid{'':<28}|\n"
            f"╰─{' '*15}─╯╰─{' '*31}─╯\n"
        )
    except phonenumbers.phonenumberutil.NumberParseException:
        result = f"[!] Error: Invalid phone number format for '{phone_number}'.\n"
    return result


def autoscan_dns_lookup(domain):
    if not domain:
        return "[!] Error: Domain was not provided for DNS lookup.\n"
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
    result_output = f"\n--- DNS Lookup for {domain} ---\n"
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            result_output += f"  [+] {rtype} Records:\n"
            for ans in answers:
                result_output += f"      - {str(ans)}\n"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue 
        except Exception as e:
            result_output += f"  [!] Error retrieving {rtype} records: {str(e)}\n"
    return result_output


def autoscan_email_lookup(email_address):
    if not email_address:
        return "[!] Error: Email address was not provided.\n"
    try:
        v = validate_email(email_address)
        email_domain = v.domain
    except EmailNotValidError as e:
        return f"[!] Invalid email format for '{email_address}': {str(e)}\n"
    
    mx_records = []
    try:
        answers = dns.resolver.resolve(email_domain, 'MX')
        for rdata in answers:
            mx_records.append(str(rdata.exchange))
    except Exception:
        pass 
    
    validity = "MX Records Found (Likely Deliverable)" if mx_records else "No MX Records (Likely Undeliverable)"
    result = (
        f"--- Email Info for {email_address} ---\n"
        f"  [+] Domain: {email_domain}\n"
        f"  [+] MX Records: {', '.join(mx_records) if mx_records else 'None'}\n"
        f"  [+] Validity: {validity}\n"
    )
    return result


def autoscan_reverse_phone_lookup(phone_number):
    if not phone_number:
        return "[!] Error: Phone number was not provided for reverse lookup.\n"
    if not PERPLEXITY_API_KEY or PERPLEXITY_API_KEY == "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":
        return "[!] Reverse phone lookup skipped: Perplexity API key not configured.\n"
        
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "You are a reverse-phone-lookup analyst. Identify the person or business most often linked to the given number. Return only publicly sourced facts, covering name, location, and context. Flag uncertainties and rate confidence."},
            {"role": "user", "content": f"Perform a reverse lookup for: {phone_number}"}
        ], "max_tokens": 8000, "temperature": 0.5, "stream": False
    }
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()
        return data['choices'][0]['message']['content'] + "\n"
    except Exception as e:
        return f"[!] Error during reverse phone lookup: {str(e)}\n"


def autoscan_check_dnsbl(ip_address):
    if not ip_address:
        return "[!] Error: IP address was not provided for DNSBL check.\n"
    dnsbl_list = ["zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net", "b.barracudacentral.org"]
    reversed_ip = ".".join(ip_address.split(".")[::-1])
    results = []
    for dnsbl in dnsbl_list:
        try:
            dns.resolver.resolve(f"{reversed_ip}.{dnsbl}", 'A')
            results.append(dnsbl)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception:
            continue
            
    report = f"--- DNSBL Check for {ip_address} ---\n"
    if results:
        report += f"  [!] LISTED on: {', '.join(results)}\n"
    else:
        report += "  [+] IP is not listed on the tested DNSBLs.\n"
    return report

def autoscan_whois_lookup(domain):
    if not domain:
        return "[!] Error: Domain was not provided for WHOIS lookup.\n"
    try:
        data = whois.whois(domain)
        result = f"--- WHOIS Information for {domain} ---\n"
        for key, value in data.items():
            if value: 
                result += f"  [+] {key.replace('_', ' ').title():<20}: {value}\n"
    except Exception as e:
        result = f"[!] Error retrieving WHOIS info for '{domain}': {str(e)}\n"
    return result

def autoscan_fact_check_text(text_to_check: str):
    if not text_to_check:
        return "[!] Error: No text provided for fact-checking.\n"
    if not PERPLEXITY_API_KEY or PERPLEXITY_API_KEY == "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":
        return "[!] Fact-check skipped: Perplexity API key not configured.\n"

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "You are a fact-check analyst. Assess the provided passage claim-by-claim. For each, provide a verdict (True/False/Unclear), a brief rationale, and note any bias or missing context. Cite sources using Chicago style."},
            {"role": "user", "content": f"Fact-check the following text:\n\n{text_to_check}"},
        ], "max_tokens": 8000, "temperature": 0.2, "stream": False
    }
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, timeout=120)
        response.raise_for_status()
        data = response.json()
        return data['choices'][0]['message']['content'] + "\n"
    except Exception as e:
        return f"[!] Error during fact-check: {str(e)}\n"


def autoscan_predicta_search(query, query_type):
    if not query or not query_type:
        return "[!] Error: Query and query type are required for Predicta search.\n"
    api_key = "INSERT API KEY HERE" 
    if api_key == "INSERT API KEY":
         return "[!] Predicta Search skipped: API key not configured.\n"
         
    url = "https://dev.predictasearch.com/api/search"
    headers = {'x-api-key': api_key, 'Content-Type': 'application/json'}
    payload = {"query": query, "query_type": query_type, "networks": ["all"]}
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()
        return "\n--- Predicta Search Results ---\n" + json.dumps(data, indent=2) + "\n"
    except Exception as e:
        return f"[!] Predicta Search Exception: {str(e)}\n"


def autoscan_business_search(business_name: str) -> str:
    if not business_name:
        return "[!] Error: Business name was not provided.\n"
    if not PERPLEXITY_API_KEY or PERPLEXITY_API_KEY == "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":
        return "[!] Business search skipped: Perplexity API key not configured.\n"
        
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "You are a business-intelligence analyst. Compile a structured, source-cited report on the company. Cover: legal name, locations, leadership, financials, contacts, market position, and risks. Cite all facts and flag data gaps."},
            {"role": "user", "content": f"Provide general information about {business_name}."},
        ], "max_tokens": 8000, "temperature": 0.5, "stream": False
    }
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, timeout=120)
        response.raise_for_status()
        data = response.json()
        return data['choices'][0]['message']['content'] + "\n"
    except Exception as e:
        return f"[!] Error during business search: {str(e)}\n"


def autoscan_subdomain_enumeration(domain):
    if not domain:
        return "[!] Error: Domain was not provided for subdomain enumeration.\n"
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        found_subs = set(entry['name_value'] for entry in data)
        if found_subs:
            return f"\n--- Found {len(found_subs)} subdomains for {domain} ---\n" + "\n".join(f"  - {s}" for s in sorted(found_subs)) + "\n"
        else:
            return f"[!] No subdomains found for {domain}.\n"
    except Exception as e:
        return f"[!] Subdomain enumeration error: {str(e)}\n"


def autoscan_relationship_search(query: str):
    if not query:
        return "[!] Error: Query was not provided for relationship search.\n"
    if not PERPLEXITY_API_KEY or PERPLEXITY_API_KEY == "INSERT API KEY HERE":
        return "[!] Relationship search skipped: Perplexity API key not configured.\n"

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "You are a relationship-mapping analyst. Deliver a fully sourced dossier on the entities in the query. Include an overview, categorized links, timeline, and a network map summary. Cite every fact and omit unsupported claims."},
            {"role": "user", "content": query}
        ], "max_tokens": 8000, "temperature": 0.5, "stream": False
    }
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, timeout=120)
        response.raise_for_status()
        data = response.json()
        return data['choices'][0]['message']['content'] + "\n"
    except Exception as e:
        return f"[!] Error during relationship search: {str(e)}\n"

def autoscan_castrick_email_search(email):
    if not email:
        return "[!] Error: Email was not provided for Castrick search.\n"
    api_key = "INSERT API KEY HERE" 
    if api_key == "INSERT API KEY":
        return "[!] Castrick Search skipped: API key not configured.\n"
        
    headers = {"api-key": api_key}
    url = f"https://api.castrickclues.com/api/v1/search?query={email}&type=email"
    try:
        response = requests.get(url, headers=headers, timeout=60)
        response.raise_for_status()
        data = response.json()
        return "\n--- Castrick Email Search Results ---\n" + json.dumps(data, indent=2) + "\n"
    except Exception as e:
        return f"[!] Castrick Search Exception: {str(e)}\n"

def autoscan_person_search(full_name: str, city: str):
    if not full_name:
        return "[!] Error: Full name was not provided for person search.\n"
    if not PERPLEXITY_API_KEY or PERPLEXITY_API_KEY == "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":
        return "[!] Person search skipped: Perplexity API key not configured.\n"
        
    query = f"{full_name} in {city}" if city else full_name
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "You are a people-profile analyst. Build a source-cited dossier on the target individual, covering their full name, birth details, residence, education, career, public roles, family links, public contact info, and recent activities. Disambiguate the name first. Cite all facts and flag data gaps."},
            {"role": "user", "content": f"Provide detailed background for: {query}"}
        ], "max_tokens": 8000, "temperature": 0.5, "stream": False
    }
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, timeout=120)
        response.raise_for_status()
        data = response.json()
        return data['choices'][0]['message']['content'] + "\n"
    except Exception as e:
        return f"[!] Error during person search: {str(e)}\n"

def autoscan_search():
    clear()
    Write.Print("[!] > AutoScan Search - Enter all known information\n", Colors.white, interval=0)
    full_name = Write.Input("[?] > Target's Full Name: ", default_color, interval=0).strip()
    city = Write.Input("[?] > Target's City: ", default_color, interval=0).strip()
    phone = Write.Input("[?] > Target's Phone Number: ", default_color, interval=0).strip()
    ip = Write.Input("[?] > Target's IP Address: ", default_color, interval=0).strip()
    email = Write.Input("[?] > Target's Email Address: ", default_color, interval=0).strip()
    whois_domain = Write.Input("[?] > Target's Domain Name: ", default_color, interval=0).strip()
    username = Write.Input("[?] > Target's Username: ", default_color, interval=0).strip()

    output_log = f"AutoScan Search Results for '{full_name or 'N/A'}'\n" + "="*80 + "\n"

    if full_name:
        Write.Print("\n[+] Running Person Search Lookup...", Colors.white, interval=0)
        output_log += "\n--- Person Search ---\n" + autoscan_person_search(full_name, city)
        
        Write.Print("\n[+] Running Business Search (using person's name)...", Colors.white, interval=0)
        output_log += "\n--- Business Search ---\n" + autoscan_business_search(full_name)

        Write.Print("\n[+] Running Relationship Search...", Colors.white, interval=0)
        output_log += "\n--- Relationship Search ---\n" + autoscan_relationship_search(full_name)
    
    if ip:
        Write.Print("\n[+] Running IP Address Search...", Colors.white, interval=0)
        output_log += "\n--- IP Address Search ---\n" + autoscan_ip_info(ip)
        
        Write.Print("\n[+] Running DNSBL Search...", Colors.white, interval=0)
        output_log += "\n--- DNSBL Search ---\n" + autoscan_check_dnsbl(ip)
    
    if username:
        Write.Print("\n[+] Running Deep Account Search...", Colors.white, interval=0)
        output_log += "\n--- Deep Account Search ---\n" + autoscan_deep_account_search(username)
    
    if phone:
        Write.Print("\n[+] Running Phone Info Search...", Colors.white, interval=0)
        output_log += "\n--- Phone Info Search ---\n" + autoscan_phone_info(phone)
        
        Write.Print("\n[+] Running Reverse Phone Search...", Colors.white, interval=0)
        output_log += "\n--- Reverse Phone Search ---\n" + autoscan_reverse_phone_lookup(phone)
    
    if email:
        Write.Print("\n[+] Running Castrick Email Search...", Colors.white, interval=0)
        output_log += "\n--- Castrick Email Search ---\n" + autoscan_castrick_email_search(email)

        Write.Print("\n[+] Running Predicta Search (Email)...", Colors.white, interval=0)
        output_log += "\n--- Predicta Search (Email) ---\n" + autoscan_predicta_search(email, "email")
        
        email_domain = email.split("@")[-1]
        Write.Print(f"\n[+] Running DNS Record Search for '{email_domain}'...", Colors.white, interval=0)
        output_log += "\n--- DNS Record Search ---\n" + autoscan_dns_lookup(email_domain)
        
        Write.Print(f"\n[+] Running Subdomain Search for '{email_domain}'...", Colors.white, interval=0)
        output_log += "\n--- Subdomain Search ---\n" + autoscan_subdomain_enumeration(email_domain)
    
    if whois_domain:
        Write.Print(f"\n[+] Running WHOIS Search for '{whois_domain}'...", Colors.white, interval=0)
        output_log += "\n--- WHOIS Search ---\n" + autoscan_whois_lookup(whois_domain)

    Write.Print("\n[+] Running Final AI Fact-Check on aggregated results...", Colors.white, interval=0)
    fact_check_result = autoscan_fact_check_text(output_log)
    output_log += "\n--- Final AI Fact-Check Analysis ---\n" + fact_check_result

    clear()
    Write.Print("\n[!] > AutoScan Search Completed. Displaying aggregated results:\n", Colors.green, interval=0)
    print(output_log)

    log_option(output_log)
    restart()

def conflict_search():
    clear()
    Write.Print("[!] > Analyze potential conflicts of interest between people, organizations, or businesses:\n",
                default_color, interval=0)
    entity1 = Write.Input("[?] > Enter the first name or entity: ", default_color, interval=0).strip()
    entity2 = Write.Input("[?] > Enter the second name or entity: ", default_color, interval=0).strip()

    def handle_error(msg):
        Write.Print(msg, Colors.red, interval=0)
        restart()
        return None

    if not entity1 or not entity2:
        return handle_error("[!] > No query provided. Please enter two valid names or entities.\n")
    if entity1.lower() == entity2.lower():
        return handle_error("[!] > Both inputs refer to the same entity. Please enter two distinct names or entities.\n")

    base_prompt = (
        "You are a conflict-of-interest analyst.\n\n"
        "Task: assess potential bias between the two named entities.\n"
        "Evaluate six dimensions:\n"
        "• Financial ties (transactions, investments, contingent pay)\n"
        "• Personal ties (family, friendship, gifts, past disputes)\n"
        "• Professional ties (employment, boards, collaborations, rivalries)\n"
        "• Power imbalance (decision authority, resource control)\n"
        "• Institutional links (shared affiliations, funding, political alignment)\n"
        "• Transparency lapses (undisclosed links, selective disclosure)\n\n"
        "Output — structured:\n"
        "1. Brief overview of each entity with inline [#] citations\n"
        "2. Categorised relationships (business, personal, philanthropic, etc.)\n"
        "3. Dated timeline of key interactions\n"
        "4. Evidence-based rating of each link’s strength and any red flags\n"
        "5. Network map summary of direct & indirect ties\n\n"
        "Rules: cite every fact inline; omit unsupported claims; mark speculation; "
        "finish with ‘Sources:’ followed by Chicago-style numbered references."
    )

    combined_query = (
        f"Analyze potential conflicts of interest between '{entity1}' and '{entity2}'. "
        "Identify any bias or red flags."
    )

    payload_conflict = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": combined_query}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True
    }

    output_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_conflict, stream=True)
        if response.status_code == 200:
            output_text += "\nConflict of Interest Analysis Results:\n"
            for line in response.iter_lines():
                if line:
                    try:
                        decoded_line = line.decode("utf-8").strip()
                        if decoded_line.startswith("data: "):
                            data_str = decoded_line[len("data: "):].strip()
                            if data_str == "[DONE]":
                                break
                            data_chunk = json.loads(data_str)
                            content_chunk = data_chunk["choices"][0].get("delta", {}).get("content", "")
                            if content_chunk:
                                print(content_chunk, end="", flush=True)
                                output_text += content_chunk
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        output_text += error_msg
        elif response.status_code == 404:
            err_msg = f"Error: Not Found (404) - {response.text}\n"
            Write.Print(err_msg, Colors.red, interval=0)
            output_text = err_msg
        else:
            err_msg = f"Error: {response.status_code}, {response.text}\n"
            Write.Print(err_msg, Colors.red, interval=0)
            output_text = err_msg
    except Exception as e:
        output_text = f"[!] > Exception in conflict analysis: {str(e)}\n"
        Write.Print(output_text, Colors.red, interval=0)
    
    log_option(output_text)
    restart()

def ipstack_lookup(ip_address):
    api_key = "INSERT API KEY HERE"

    try:

        conn = http.client.HTTPSConnection("api.ipstack.com")
        endpoint = f"/{ip_address}?access_key={api_key}"
        conn.request("GET", endpoint)
        res = conn.getresponse()
        data = res.read()

        return json.loads(data.decode("utf-8"))

    except http.client.HTTPException as http_err:
        return f"HTTP error occurred: {http_err}"
    except Exception as err:
        return f"An error occurred: {err}"
    
def veriphone_lookup(phone_number):
    try:
        api_key = "INSERT API KEY HERE"
        conn = http.client.HTTPSConnection("api.veriphone.io")
        endpoint = f"/v2/verify?phone={phone_number}&key={api_key}"
        conn.request("GET", endpoint)
        res = conn.getresponse()
        data = res.read()
        return json.loads(data.decode("utf-8"))

    except http.client.HTTPException as http_err:
        return f"HTTP error occurred: {http_err}"
    except Exception as err:
        return f"An error occurred: {err}"
    
def numverify_lookup(phone_number):
    try:
        api_key = "INSERT API KEY HERE"
        conn = http.client.HTTPConnection("apilayer.net")
        endpoint = f"/api/validate?access_key={api_key}&number={phone_number}"
        conn.request("GET", endpoint)
        res = conn.getresponse()
        data = res.read()
        return json.loads(data.decode("utf-8"))

    except http.client.HTTPException as http_err:
        return f"HTTP error occurred: {http_err}"
    except Exception as err:
        return f"An error occurred: {err}"

def osint_investigation_search():
    clear()
    Write.Print("[!] > OSINT Investigation Search\n", Colors.white, interval=0)

    query = Write.Input(
        "[?] > Enter search query for OSINT investigation: ",
        Colors.white,
        interval=0,
    ).strip()
    if not query:
        Write.Print("[!] > Please enter a search query.\n", Colors.red, interval=0)
        restart()
        return

    encoded_query = urllib.parse.quote(query)
    conn = http.client.HTTPSConnection("osint-tool-investigation.p.rapidapi.com")
    headers = {
        "x-rapidapi-key": "INSERT API KEY HERE",
        "x-rapidapi-host": "osint-tool-investigation.p.rapidapi.com",
    }
    conn.request("GET", f"/api/search?request={encoded_query}", headers=headers)

    res = conn.getresponse()
    data = res.read()
    raw_result = data.decode("utf-8")

    try:
        parsed = json.loads(raw_result)
        pretty_result = json.dumps(parsed, indent=4, ensure_ascii=False)
    except json.JSONDecodeError:
        pretty_result = "\n".join(
            textwrap.fill(line, width=120) for line in raw_result.splitlines()
        )

    Write.Print(pretty_result + "\n", Colors.white, interval=0)
    log_option(pretty_result)

    print("[?] Export OSINT investigation search results to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json(
            {"query": query, "results": parsed if "parsed" in locals() else raw_result},
            filename_prefix="osint_investigation_search",
        )

    restart()

def contact_extractor():
    clear()
    Write.Print("[!] > Contact Extractor\n", Colors.white, interval=0)

    first_name = Write.Input("[?] > Enter the target's first name: ", default_color, interval=0).strip()
    last_name  = Write.Input("[?] > Enter the target's last name: ",  default_color, interval=0).strip()
    city       = Write.Input("[?] > Enter the target's city (optional): ", default_color, interval=0).strip()

    if not first_name or not last_name:
        Write.Print("[!] > Please enter a valid first and last name.\n", Colors.red, interval=0)
        restart()
        return

    if not PERPLEXITY_API_KEY or PERPLEXITY_API_KEY == "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":
        Write.Print("[!] > Contact extraction skipped: Perplexity API key not configured.\n", Colors.red, interval=0)
        restart()
        return

    target = f"{first_name} {last_name}" if not city else f"{first_name} {last_name}, {city}"

    base_prompt = (
        "You are a contact-intelligence analyst.\n\n"
        "Task: gather verifiable, up-to-date contact details for the named person.\n"
        "Required fields (with confidence score):\n"
        "• Primary email(s)\n"
        "• Direct phone(s)\n"
        "• Physical address or HQ\n"
        "• Social-media / professional profiles\n"
        "• Current employer & role\n\n"
        "Method: consult openly accessible sources—business directories, corporate sites, professional networks, "
        "public filings, and news. Cross-check at least two sources per datum. Provide source footnotes [#] and a "
        "brief note on retrieval method. Output only contact-relevant data."
    )

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": f"Provide comprehensive contact information for: {target}"}
        ],
        "max_tokens": 4096,
        "temperature": 0.5,
        "stream": True
    }

    try:
        response = requests.post(
            PERPLEXITY_API_URL,
            headers=perplexity_headers,
            json=payload,
            stream=True,
            timeout=480
        )
        response.raise_for_status()

        collected = []
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            if line.startswith("data: "):
                line = line[6:]
            if line == "[DONE]":
                break
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            delta = obj.get("choices", [{}])[0].get("delta", {}).get("content")
            if delta:
                Write.Print(delta, Colors.white, interval=0)
                collected.append(delta)

        result = "".join(collected) + "\n"

    except Exception as e:
        result = f"[!] Error during contact extraction: {str(e)}\n"
        Write.Print(result, Colors.red, interval=0)

    log_option(result)

    Write.Input("\n[?] > Press Enter to return to the main menu...", default_color, interval=0)
    restart()

def instagram_checker():
    clear()
    Write.Print("[!] > Instagram Checker\n", default_color, interval=0)
    email = Write.Input("[?] > Enter the email to check for Instagram: ", default_color, interval=0).strip()
    if not email:
        clear()
        Write.Print("[!] > Please enter a valid email address.\n", Colors.red, interval=0)
        restart()
        return

    conn = http.client.HTTPSConnection("instagram-checker.p.rapidapi.com")
    payload = '{"input": "' + email + '"}'
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "instagram-checker.p.rapidapi.com",
        'Content-Type': "application/json"
    }

    conn.request("POST", "/check", payload, headers)
    res = conn.getresponse()
    data = res.read()
    result = data.decode("utf-8")

    clear()
    Write.Print(result, Colors.white, interval=0)
    log_option(result)
    restart()

def face_similarity():
    clear()
    Write.Print("[!] > Face Similarity Comparison\n", default_color, interval=0)
    
    url1 = Write.Input("[?] > Enter first image URL (press Enter for default): ", default_color, interval=0).strip()
    url2 = Write.Input("[?] > Enter second image URL (press Enter for default): ", default_color, interval=0).strip()

    if not url1:
        url1 = "https://www.planetegrandesecoles.com/wp-content/uploads/2023/08/brad.jpg"
    if not url2:
        url2 = "https://e00-telva.uecdn.es/assets/multimedia/imagenes/2023/07/04/16884784570312.jpg"

    encoded_url1 = urllib.parse.quote(url1, safe='')
    encoded_url2 = urllib.parse.quote(url2, safe='')
    
    conn = http.client.HTTPSConnection("face-similarity-api.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "face-similarity-api.p.rapidapi.com"
    }

    endpoint = f"/5547/compare?hide_analysis=false&url1={encoded_url1}&url2={encoded_url2}"
    conn.request("GET", endpoint, headers=headers)
    
    res = conn.getresponse()
    data = res.read()
    result = data.decode("utf-8")
    
    clear()
    Write.Print(result, Colors.white, interval=0)
    log_option(result)
    restart()

def reverse_image_search():
    clear()
    Write.Print("[!] > Reverse Image Search\n", default_color, interval=0)
    image_url = Write.Input("[?] > Enter the image URL to search: ", default_color, interval=0).strip()
    if not image_url:
        image_url = "https://i.imgur.com/HBrB8p0.png"
    
    encoded_url = urllib.parse.quote(image_url, safe='')
    
    conn = http.client.HTTPSConnection("reverse-image-search1.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "reverse-image-search1.p.rapidapi.com"
    }
    
    endpoint = f"/reverse-image-search?url={encoded_url}&limit=10&safe_search=off"
    conn.request("GET", endpoint, headers=headers)
    
    res = conn.getresponse()
    data = res.read()
    result = data.decode("utf-8")
    
    clear()
    Write.Print(result, Colors.white, interval=0)
    log_option(result)
    restart()

def x_checker():
    clear()
    Write.Print("[!] > X Checker\n", default_color, interval=0)
    email = Write.Input("[?] > Enter the email address to check: ", default_color, interval=0).strip()
    if not email:
        clear()
        Write.Print("[!] > Please enter a valid email address.\n", Colors.red, interval=0)
        restart()
        return

    payload = f'{{"input": "{email}"}}'
    
    conn = http.client.HTTPSConnection("x-checker.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "x-checker.p.rapidapi.com",
        'Content-Type': "application/json"
    }
    
    conn.request("POST", "/check", payload, headers)
    res = conn.getresponse()
    data = res.read()
    result = data.decode("utf-8")
    
    clear()
    Write.Print(result, Colors.white, interval=0)
    log_option(result)
    restart()

def settings():
    while True:
        try:
            clear()
            print("\033[1;31m   ██████╗██╗        █████╗ ████████╗███████╗")
            print("   ██╔════╝██║       ██╔══██╗╚══██╔══╝██╔════╝")
            print("   ██║     ██║       ███████║   ██║   ███████╗")
            print("   ██║     ██║       ██╔══██║   ██║   ╚════██║")
            print("   ██████╗ ███████╗  ██║  ██║   ██║   ███████║")
            print("   ╚═════╝ ╚══════╝  ╚═╝  ╚═╝   ╚═╝   ╚══════╝\033[0m")
            print("\033[1;34mC       L      A       T       S       C       O       P       E\033[0m   \033[1;31m(Version 1.19)\033[0m")
            author = "🛡️ By Josh Clatney - Ethical Pentesting Enthusiast 🛡️"
            Write.Print(author + "\n[C.I.T]\nClatScope Info Tool\n", Colors.white, interval=0)
            settings_menu = """╭─    ─╮╭─                   ─╮╭─                                         ─╮
|  №   ||       Setting       ||                Description                |
|======||=====================||===========================================|
| [1]  || Theme change        || Customize the theme                       |
| [0]  || Back to menu        || Exit the settings                         |
╰─    ─╯╰─                   ─╯╰─                                         ─╯
"""
            Write.Print(settings_menu, Colors.white, interval=0)
            settings_choice = Write.Input("[?] >  ", default_color, interval=0).strip()
            if settings_choice == "1":
                change_color()
            elif settings_choice == "0":
                return
            else:
                clear()
                Write.Print("[!] > Invalid input.\n", Colors.red, interval=0)
        except KeyboardInterrupt:
            clear()
            Write.Print("[!] > Exiting on user request...\n", Colors.white, interval=0)
            exit()

def sherlock_username_search():
    clear()
    Write.Print("[!] > Sherlock Username Enumerator\n", default_color, interval=0)
    username = Write.Input("[?] > Enter the username: ", default_color, interval=0).strip()
    if not username:
        Write.Print("[!] > No username provided.\n", Colors.red, interval=0)
        restart()
        return

    import requests, re, threading, time, json
    from queue import Queue, Empty
    from enum import Enum
    from typing import Any, Dict

    DATA_URL          = ("https://raw.githubusercontent.com/"
                         "sherlock-project/sherlock/"
                         "master/sherlock_project/resources/data.json")
    HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
        )
    }
    MAX_WORKERS      = 100
    REQUEST_TIMEOUT  = 30
    WAF_FINGERPRINTS = [
        ".loading-spinner{visibility:hidden}body.no-js",
        '<span id="challenge-error-text">',
        "AwsWafIntegration.forceRefreshToken",
        "perimeterxIdentifiers",
    ]

    class QueryStatus(Enum):
        UNKNOWN   = "unknown"
        AVAILABLE = "available"
        CLAIMED   = "claimed"
        ILLEGAL   = "illegal"
        WAF       = "waf"
        ERROR     = "error"

    class Site:
        __slots__ = (
            "name", "url_main", "url_fmt", "error_type",
            "error_msg", "error_code", "regex_check", "headers",
            "request_method", "request_payload", "url_probe",
        )
        def __init__(self, name: str, raw: Dict[str, Any]) -> None:
            self.name            = name
            self.url_main        = raw["urlMain"]
            self.url_fmt         = raw["url"]
            self.error_type      = raw["errorType"]
            self.error_msg       = raw.get("errorMsg")
            self.error_code      = raw.get("errorCode")
            self.regex_check     = raw.get("regexCheck")
            self.headers         = raw.get("headers", {})
            self.request_method  = raw.get("request_method")
            self.request_payload = raw.get("request_payload")
            self.url_probe       = raw.get("urlProbe")

        def interpolate(self, template: Any, uname: str) -> Any:
            if isinstance(template, str):
                return template.replace("{}", uname)
            if isinstance(template, dict):
                return {k: self.interpolate(v, uname) for k, v in template.items()}
            if isinstance(template, list):
                return [self.interpolate(v, uname) for v in template]
            return template

    def fetch_site_data(url: str = DATA_URL) -> Dict[str, "Site"]:
        raw = requests.get(url, timeout=REQUEST_TIMEOUT).json()
        raw.pop("$schema", None)
        return {n: Site(n, v) for n, v in raw.items()}

    def probe(site: "Site", uname: str, sess: requests.Session) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "site": site.name,
            "url_main": site.url_main,
            "url_user": "",
            "status": QueryStatus.UNKNOWN,
            "http_status": None,
            "elapsed": None,
        }
        if site.regex_check and re.search(site.regex_check, uname) is None:
            res["status"] = QueryStatus.ILLEGAL
            return res

        url_user  = site.interpolate(site.url_fmt,  uname.replace(" ", "%20"))
        url_probe = site.interpolate(site.url_probe, uname) if site.url_probe else url_user
        res["url_user"] = url_user

        verb  = site.request_method or ("HEAD" if site.error_type == "status_code" else "GET")
        call  = getattr(sess, verb.lower(), sess.get)
        hdrs  = HEADERS.copy(); hdrs.update(site.headers or {})
        body  = site.interpolate(site.request_payload, uname) if site.request_payload else None
        allow = site.error_type != "response_url"

        t0 = time.perf_counter()
        try:
            r = call(url_probe, headers=hdrs, allow_redirects=allow,
                     timeout=REQUEST_TIMEOUT, json=body)
        except Exception:
            res["status"]  = QueryStatus.ERROR
            res["elapsed"] = round(time.perf_counter() - t0, 3)
            return res
        res["elapsed"]   = round(time.perf_counter() - t0, 3)
        res["http_status"] = r.status_code
        page = r.text or ""

        # ── decision
        if any(fp in page for fp in WAF_FINGERPRINTS):
            res["status"] = QueryStatus.WAF
        elif site.error_type == "message":
            flag = True
            msgs = site.error_msg
            if isinstance(msgs, str):
                flag = msgs not in page
            else:
                flag = not any(m in page for m in msgs or [])
            res["status"] = QueryStatus.CLAIMED if flag else QueryStatus.AVAILABLE
        elif site.error_type == "status_code":
            codes = site.error_code
            if isinstance(codes, int): codes = [codes]
            if codes and r.status_code in codes:
                res["status"] = QueryStatus.AVAILABLE
            elif 200 <= r.status_code < 300:
                res["status"] = QueryStatus.CLAIMED
            else:
                res["status"] = QueryStatus.AVAILABLE
        elif site.error_type == "response_url":
            res["status"] = QueryStatus.CLAIMED if (200 <= r.status_code < 300) else QueryStatus.AVAILABLE
        else:
            res["status"] = QueryStatus.ERROR
        return res

    def worker(q_in: "Queue[Site]", q_out: "Queue[Dict[str,Any]]",
               uname: str, sess: requests.Session) -> None:
        while True:
            try:
                site = q_in.get_nowait()
            except Empty:
                return
            try:
                q_out.put(probe(site, uname, sess))
            finally:
                q_in.task_done()

    Write.Print("\n[+] Fetching site index…\n", Colors.white, interval=0)
    try:
        sites = fetch_site_data()
    except Exception as e:
        Write.Print(f"[!] > Failed to fetch site list: {e}\n", Colors.red, interval=0)
        restart(); return
    total_sites = len(sites)
    Write.Print(f"[✓] Loaded {total_sites} sites.\n\n", Colors.green, interval=0)

    sess = requests.Session()
    q_in:  "Queue[Site]"          = Queue()
    q_out: "Queue[Dict[str,Any]]" = Queue()
    for s in sites.values(): q_in.put(s)

    threads = [
        threading.Thread(target=worker,
                         args=(q_in, q_out, username, sess),
                         daemon=True)
        for _ in range(min(MAX_WORKERS, total_sites))
    ]
    for t in threads: t.start()

    found, processed = [], 0
    while any(t.is_alive() for t in threads) or not q_out.empty():
        try:
            res = q_out.get(timeout=0.2)
        except Empty:
            continue
        processed += 1
        if res["status"] == QueryStatus.CLAIMED:
            found.append(res)
            Write.Print(f"[{processed:4}/{total_sites}] {res['site']:<25}  FOUND      {res['url_user']}\n",
                        Colors.green, interval=0)
        else:
            Write.Print(f"[{processed:4}/{total_sites}] {res['site']:<25}  Not found\n",
                        Colors.white, interval=0)
        q_out.task_done()

    summary_lines = []
    if found:
        summary_lines.append(f"\nAccounts found for “{username}” ({len(found)}):")
        for r in found:
            summary_lines.append(f" • {r['site']:<25} {r['url_user']}")
    else:
        summary_lines.append(f"\nNo accounts found for “{username}”.")
    summary = "\n".join(summary_lines)
    Write.Print(summary + "\n", Colors.white, interval=0)
    log_option(summary)

    print("[?] Export results to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"username": username, "results": found}, filename_prefix="sherlock_username")

    restart()

def get_ip_details(ip: str | None = None, *, timeout: float = 4.0) -> dict[str, str]:
    import ipaddress, requests, json, contextlib

    PROVIDERS = (
        f"https://ipapi.co/{ip or ''}/json/",
        f"http://ip-api.com/json/{ip or ''}?fields=status,message,query,"
        "continentCode,timezone,offset,city,regionName,zip,lat,lon,country,"
        "countryCode,as,isp",
        f"https://ipinfo.io/{ip or ''}/json",
        f"https://geolocation-db.com/json/{ip or ''}&position=true",
    )

    REQUIRED_KEYS = {
        "ip","network","version","city","region","country","country_name",
        "country_code","country_code_iso3","country_capital","country_tld",
        "continent_code","in_eu","postal_code","latitude","longitude","timezone",
        "utc_offset","country_calling_code","currency","currency_name","languages",
        "country_area_sq_km","country_population","asn","org"
    }

    def _merge(into: dict[str, str], new: dict[str, str]) -> None:
        for k, v in new.items():
            if v not in (None, "", "Unknown") and into.get(k) in (None, "", "Unknown"):
                into[k] = str(v)

    meta: dict[str, str] = {}
    for url in PROVIDERS:
        try:
            r = requests.get(url, timeout=timeout)
            r.raise_for_status()
            data = r.json()
        except Exception:
            continue

        if "ip" in data or "IPv4" in data:
            addr = data.get("ip") or data.get("IPv4") or data.get("query")
            meta.setdefault("ip", addr)
            if addr:
                meta.setdefault("version", "IPv6" if ":" in addr else "IPv4")

        if "network" in data:
            meta.setdefault("network", data["network"])

        for k in (
            "city","region","asn","org","latitude","longitude","timezone","utc_offset",
            "country_calling_code","currency","currency_name","languages","postal",
            "country","country_name","country_code","country_code_iso3","country_capital",
            "country_tld","continent_code","in_eu","country_area","country_population",
        ):
            if k in data:
                key_out = {
                    "postal":       "postal_code",
                    "country_area": "country_area_sq_km",
                }.get(k, k)
                meta.setdefault(key_out, data[k])

        if data.get("status") == "success":
            meta.setdefault("country",          data.get("countryCode"))
            meta.setdefault("country_name",     data.get("country"))
            meta.setdefault("continent_code",   data.get("continentCode"))
            meta.setdefault("city",             data.get("city"))
            meta.setdefault("region",           data.get("regionName"))
            meta.setdefault("postal_code",      data.get("zip"))
            meta.setdefault("latitude",         data.get("lat"))
            meta.setdefault("longitude",        data.get("lon"))
            meta.setdefault("timezone",         data.get("timezone"))
            meta.setdefault("org",              data.get("isp"))
            meta.setdefault("asn",              data.get("as"))
            off = data.get("offset")
            if off is not None:
                hh, mm = divmod(abs(int(off)), 3600)
                sign   = "+" if off >= 0 else "-"
                meta.setdefault("utc_offset", f"{sign}{hh:02d}:{mm//60:02d}")

        if "loc" in data:
            try:
                lat, lon = (float(x) for x in data["loc"].split(","))
                meta.setdefault("latitude", lat)
                meta.setdefault("longitude", lon)
            except Exception:
                pass

        if "country_code" in data:
            meta.setdefault("country",      data.get("country_code"))
            meta.setdefault("country_name", data.get("country_name"))
            meta.setdefault("city",         data.get("city"))
            meta.setdefault("region",       data.get("state"))
            meta.setdefault("postal_code",  data.get("postal"))

        if all(k in meta for k in REQUIRED_KEYS):
            break

    with contextlib.suppress(ValueError):
        if "ip" in meta and "network" not in meta:
            meta["network"] = (
                f"{meta['ip']}/32" if ipaddress.ip_address(meta['ip']).version == 4
                                   else f"{meta['ip']}/128"
            )

    EU = {"AT","BE","BG","HR","CY","CZ","DK","EE","FI","FR","DE","GR","HU","IE",
          "IT","LV","LT","LU","MT","NL","PL","PT","RO","SK","SI","ES","SE"}
    if "in_eu" not in meta and meta.get("country") in EU:
        meta["in_eu"] = "Yes"

    for k in REQUIRED_KEYS:
        meta.setdefault(k, "Unknown")

    if isinstance(meta["in_eu"], bool):
        meta["in_eu"] = "Yes" if meta["in_eu"] else "No"
    elif str(meta["in_eu"]).lower() not in ("yes","no"):
        meta["in_eu"] = "Unknown"

    return meta

SPAM_API_KEY = "INSERT API KEY HERE"
SPAM_BASE_URL = "https://api.apilayer.com/spamchecker"
SPAM_THRESHOLD = 5

def spam_checker_tool():
    clear()
    Write.Print("[!] > APILayer Spam Checker\n", default_color, interval=0)
    Write.Print("Paste text to check for spam (Enter on empty line to return)…\n", Colors.white, interval=0)
    while True:
        text = Write.Input("[?] > ", Colors.white, interval=0)
        if text == "":
            restart()
            return
        try:
            url = f"{SPAM_BASE_URL}?threshold={SPAM_THRESHOLD}"
            headers = {"apikey": SPAM_API_KEY}
            resp = requests.post(url, headers=headers, data=text.encode("utf-8"), timeout=60)
            resp.raise_for_status()
            data = resp.json()
            verdict = "SPAM" if data.get("spam") else "HAM"
            score = data.get("score")
            out = f"Verdict: {verdict}\nScore: {score}\nFull JSON:\n{json.dumps(data, indent=2, ensure_ascii=False)}"
            clear()
            Write.Print(out + "\n", Colors.white, interval=0)
            log_option(out)
            restart()
            return
        except Exception as exc:
            Write.Print(f"[!] > Error: {str(exc)}\n", Colors.red, interval=0)
            restart()
            return

def website_contact_scraper(url: str) -> None:
    import re, json, textwrap, requests
    from bs4 import BeautifulSoup

    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url

    EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    PHONE_RE = re.compile(r"(?:\+?\d{1,3}[\s\-.])?(?:\(?\d{3}\)?[\s\-.])?\d{3}[\s\-.]\d{4}", re.VERBOSE)
    FAX_HINTS = re.compile(r"\b(?:fax|facsimile)\b", re.I)
    SOCIAL_RE = re.compile(
        r"https?://(?:www\.)?(facebook|twitter|linkedin|instagram|youtube|t\.me|telegram|pinterest|threads|mastodon)\.[^\s\"'<>]+",
        re.I,
    )

    def _is_repeating_chars(s: str) -> bool:
        cleaned = re.sub(r"[^0-9a-z]", "", s.lower())
        return bool(cleaned) and len(set(cleaned)) == 1

    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        html = resp.text
        soup = BeautifulSoup(html, "html.parser")  

        emails, phones, faxes, socials = [], [], [], []
        seen_emails, seen_digits, seen_social = set(), set(), set()

        for raw in EMAIL_RE.findall(html):
            canon = raw.lower()
            if _is_repeating_chars(canon) or canon in seen_emails:
                continue
            seen_emails.add(canon)
            emails.append(raw)

        for m in PHONE_RE.finditer(html):
            raw_num = m.group(0).strip()
            digits = re.sub(r"\D", "", raw_num)
            if len(digits) < 10 or _is_repeating_chars(digits) or digits in seen_digits:
                continue
            seen_digits.add(digits)
            ctx = html[max(m.start() - 60, 0) : m.start()].lower()
            (faxes if FAX_HINTS.search(ctx) else phones).append(raw_num)

        for m in SOCIAL_RE.finditer(html):
            url_found = m.group(0)
            if _is_repeating_chars(url_found) or url_found in seen_social:
                continue
            seen_social.add(url_found)
            socials.append(url_found)

        def _fmt(vals):
            return ", ".join(vals) if vals else "None found"

        data = {
            "Emails": _fmt(emails),
            "Phone Numbers": _fmt(phones),
            "Fax Numbers": _fmt(faxes),
            "Social Profiles": _fmt(socials),
        }

        clear()
        Write.Print(json.dumps(data, indent=2, ensure_ascii=False) + "\n", Colors.white, interval=0)
        log_option(json.dumps(data, indent=2, ensure_ascii=False))

        print("[?] Export contact info to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({"url": url, "contact_info": data}, filename_prefix="contact_info")

    except requests.exceptions.Timeout:
        clear()
        Write.Print("[!] > Timeout fetching the URL.\n", Colors.red, interval=0)
    except Exception as exc:
        clear()
        Write.Print(f"[!] > Unexpected error: {exc}\n", Colors.red, interval=0)

    restart()

def email_verification_check(email: str) -> None:
    import json, requests

    API_URL = "https://api.email-validator.net/api/verify"
    _API_KEY = "INSERT API KEY HERE"
    _VALID_CODES = {200, 207, 215}
    _RETRYABLE_CODES = {114, 118, 215, 313, 314}

    payload = {"EmailAddress": email, "APIKey": _API_KEY}

    try:
        resp = requests.post(API_URL, data=payload, timeout=15)
        if resp.status_code != 200:
            clear()
            Write.Print(
                f"[!] > Email-Validator error: HTTP {resp.status_code}\n{resp.text}\n",
                Colors.red, interval=0
            )
            restart()
            return

        try:
            data = resp.json()
        except json.JSONDecodeError:
            clear()
            Write.Print("[!] > Non-JSON response from API.\n", Colors.red, interval=0)
            restart()
            return

        status = int(data.get("status", 0))
        is_valid = status in _VALID_CODES
        retryable = status in _RETRYABLE_CODES

        report = f"""
╭─{' '*78}─╮
|{' '*27}Email Verification Report{' '*26}|
|{'='*80}|
| [+] > Email Address      || {email:<51}|
| [+] > Status Code        || {status:<51}|
| [+] > Info               || {data.get('info','N/A'):<51}|
| [+] > Details            || {data.get('details','N/A'):<51}|
| [+] > Deliverable?       || {('YES' if is_valid else 'NO'):<51}|
| [+] > Retryable?         || {('YES' if retryable else 'NO'):<51}|
╰─{' '*78}─╯
"""
        clear()
        Write.Print(report, Colors.white, interval=0)
        log_option(report)

        print("[?] Export Email Verification report to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json(
                {"email": email, "verification_result": data},
                filename_prefix="email_verification"
            )

    except requests.exceptions.Timeout:
        clear()
        Write.Print("[!] > Timeout contacting Email-Validator API.\n", Colors.red, interval=0)
    except Exception as exc:
        clear()
        Write.Print(f"[!] > Unexpected error: {exc}\n", Colors.red, interval=0)

    restart()

SHERLOCKEYE_API_KEY = "INSERT API KEY HERE"
SHERLOCKEYE_BASE_URL = "https://api.sherlockeye.io/search"

def sherlockeye_username_search_tool():
    clear()
    Write.Print("[!] > SherlockEye Username Search\n", default_color, interval=0)
    username = Write.Input("[?] > Enter the username (blank to return): ", default_color, interval=0).strip()
    if username == "":
        restart()
        return
    try:
        import requests, json, datetime
        headers = {
            "Authorization": f"Bearer {SHERLOCKEYE_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "type": "username",
            "value": username
        }
        resp = requests.post(SHERLOCKEYE_BASE_URL, headers=headers, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        pretty = json.dumps(data, indent=2, ensure_ascii=False)
        clear()
        Write.Print(pretty + "\n", Colors.white, interval=0)
        log_option(pretty)
        filename_prefix = "sherlockeye_username"
        print("[?] Export results to TXT? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            fname = f"{filename_prefix}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(fname, "w", encoding="utf-8") as f:
                f.write(pretty)
        print("[?] Export results to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({"username": username, "results": data}, filename_prefix=filename_prefix)
    except Exception as exc:
        clear()
        Write.Print(f"[!] > Error: {exc}\n", Colors.red, interval=0)
    restart()

def sherlockeye_get_result_tool():
    clear()
    Write.Print("[!] > SherlockEye Get Result\n", default_color, interval=0)
    search_id = Write.Input(
        "[?] > Enter SherlockEye search ID (blank to return): ",
        default_color, interval=0
    ).strip()

    if search_id == "":
        restart()
        return

    try:
        import requests, json, datetime
        headers = {"Authorization": f"Bearer {SHERLOCKEYE_API_KEY}"}
        url = f"https://api.sherlockeye.io/get/{search_id}"
        resp = requests.get(url, headers=headers, timeout=60)
        resp.raise_for_status()
        data = resp.json()

        pretty = json.dumps(data, indent=2, ensure_ascii=False)
        clear()
        Write.Print(pretty + "\n", Colors.white, interval=0)
        log_option(pretty)

        print("[?] Export results to TXT? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            fname = (
                f"sherlockeye_result_"
                f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            with open(fname, "w", encoding="utf-8") as f:
                f.write(pretty)

        print("[?] Export results to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json(
                {"search_id": search_id, "results": data},
                filename_prefix="sherlockeye_result"
            )

    except Exception as exc:
        clear()
        Write.Print(f"[!] > Error: {exc}\n", Colors.red, interval=0)

    restart()

def change_color():
    global default_color
    clear()
    color_menu = """
╭─    ─╮╭─                     ─╮
|  №   ||         Color         |
|======||=======================|
| [1]  || Red                   |
| [2]  || Blue                  |
| [3]  || Green                 |
| [4]  || Yellow                |
| [5]  || Cyan                  |
| [6]  || White                 |
|------||-----------------------|
| [0]  || Back to settings menu |
╰─    ─╯╰─                     ─╯
"""
    Write.Print(color_menu, Colors.white, interval=0)
    color_choice = Write.Input("\n\n[?] >  ", default_color, interval=0).strip()
    color_map = {
        "1": Colors.red,
        "2": Colors.blue,
        "3": Colors.green,
        "4": Colors.yellow,
        "5": Colors.cyan,
        "6": Colors.white
    }
    if color_choice in color_map:
        default_color = color_map[color_choice]
        clear()
        Write.Print("[!] > Colour has been changed.\n", default_color, interval=0)
    elif color_choice == "0":
        settings()
    else:
        clear()
        Write.Print("[!] > Invalid choice.\n", Colors.red, interval=0)
    restart()

def main():
    while True:
        try:
            clear()
            print("\033[1;31m ██████╗██╗      █████╗ ████████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗")
            print("██╔════╝██║     ██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝")
            print("██║     ██║     ███████║   ██║   ███████╗██║     ██║   ██║██████╔╝█████╗  ")
            print("██║     ██║     ██╔══██║   ██║   ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  ")
            print("╚██████╗███████╗██║  ██║   ██║   ███████║╚██████╗╚██████╔╝██║     ███████╗")
            print(" ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝\033[0m")
            print("\033[1;34mC L A T S C O P E       I N F O       T O O L\033[0m   \033[1;31m(Version 1.19)\033[0m")
            author = "🛡️ By Joshua M Clatney (Clats97) - Ethical Pentesting Enthusiast 🛡️"
            Write.Print(author + "\n[OSINT]\nOpen Sources. Clear Conclusions\n", Colors.white, interval=0)
            menu = (
                "==============================================================================================================|\n"
                "|  №   ||         Function          ||                          Description                                   |\n"
                "|======||===========================||========================================================================|\n"
                "| [1]  || IP Address Search         || Retrieves IP address info                                              |\n"
                "| [2]  || Deep Account Search       || Retrieves profiles from various websites                               |\n"
                "| [3]  || Phone Search              || Retrieves phone number info                                            |\n"
                "| [4]  || DNS Record Search         || Retrieves DNS records (A, CNAME, MX, NS)                               |\n"
                "| [5]  || Email MX Search           || Retrieves MX info for an email                                         |\n"
                "| [6]  || Person Name Search        || Retrieves extensive person info                                        |\n"
                "| [7]  || Reverse DNS Search        || Retrieves PTR records for an IP address                                |\n"
                "| [8]  || Email Header Search       || Retrieves info from an email header                                    |\n"
                "| [9]  || Email Breach Search       || Retrieves email breach info (HIBP)                                     |\n"
                "| [10] || WHOIS Search              || Retrieves domain registration data                                     |\n"
                "| [11] || Password Analyzer         || Retrieves password strength rating                                     |\n"
                "| [12] || Username Search           || Retrieves usernames from online accounts                               |\n"
                "| [13] || Reverse Phone Search      || Retrieves references to a phone number                                 |\n"
                "| [14] || SSL Search                || Retrieves basic SSL certificate details from a URL                     |\n"
                "| [15] || Web Crawler Search        || Retrieves Robots.txt & Sitemap.xml file info                           |\n"
                "| [16] || DNSBL Search              || Retrieves IP DNS blacklist info                                        |\n"
                "| [17] || Web Metadata Search       || Retrieves meta tags and more from a webpage                            |\n"
                "| [18] || Travel Risk Search        || Retrieves a detailed travel risk assessment                            |\n"
                "| [19] || Botometer Search          || Retrieves a Botometer score for an X/Twitter user account              |\n"
                "| [20] || Business Search           || Retrieves general information about a business                         |\n"
                "| [21] || HR Email Search           || Retrieves infostealer email infection data (Hudson Rock)               |\n"
                "| [22] || HR Username Search        || Retrieves infostealer username infection data (Hudson Rock)            |\n"
                "| [23] || HR Domain Search          || Retrieves infostealer domain infection data (Hudson Rock)              |\n"
                "| [24] || HR IP Search              || Retrieves infostealer IP address infection data (Hudson Rock)          |\n"
                "| [25] || Fact Check Search         || Retrieves analysis of input text for truthfulness                      |\n"
                "| [26] || Relationship Search       || Retrieves & maps info between entities/people/businesses               |\n"
                "| [27] || File Metadata Search      || Retrieves metadata from various file types                             |\n"
                "| [28] || Subdomain Search          || Retrieves subdomain info                                               |\n"
                "| [29] || Domain Search             || Retrieves domain info using Hunter.io                                  |\n"
                "| [30] || Email Search              || Retrieves email info using Hunter.io                                   |\n"
                "| [31] || Email Verify Search       || Retrieves email verification using Hunter.io                           |\n"
                "| [32] || Company Search            || Retrieves company enrichment using Hunter.io                           |\n"
                "| [33] || Person Info Search        || Retrieves person enrichment using Hunter.io                            |\n"
                "| [34] || Combined Search           || Retrieves combined enrichment using Hunter.io                         |\n"
                "| [35] || Email Search (Castrick)   || Retrieves in-depth info on someone by email                            |\n"
                "| [36] || Virus Search              || Retrieves a VirusTotal report for a domain                             |\n"
                "| [37] || Malice Search             || Retrieves info related to potential malicious content/scams            |\n"
                "| [38] || Supply/Vendor Search      || Retrieves comprehensive risk assessment for supply/vendors             |\n"
                "| [39] || Business Rep Search       || Retrieves a business reputation overview                               |\n"
                "| [40] || Wayback Search            || Retrieves historical snapshots from the Wayback Machine                |\n"
                "| [41] || Port Scan Search          || Retrieves scan results on common ports                                 |\n"
                "| [42] || Bulk CSV Search           || Retrieves multiple checks in bulk from a CSV for domain/IP             |\n"
                "| [43] || Phone Leak Search         || Retrieves leaks related to a phone number                              |\n"
                "| [44] || AES Encryption            || Encrypts plaintext using AES-256-CBC encryption with an IV             |\n"
                "| [45] || AES Decryption            || Decrypts ciphertext using AES-256-CBC decryption with an IV            |\n"
                "| [46] || Email Intel Search        || Retrieves an email intelligence check based on user input              |\n"
                "| [47] || Truecaller Search         || Retrieves phone number info using Truecaller                           |\n"
                "| [48] || Skip Trace Search         || Retrieves a skip trace overview by name                                |\n"
                "| [49] || Skip Trace ID Search      || Retrieves a skip trace overview by ID                                  |\n"
                "| [50] || Ship Search v1            || Retrieves ship data by searching an MMSI                               |\n"
                "| [51] || Ship Search v2            || Retrieves ship data by searching a location (via radius)               |\n"
                "| [52] || Aircraft Search v1        || Retrieves aircraft data by searching a location                        |\n"
                "| [53] || Aircraft Search v2        || Retrieves aircraft data by searching a callsign                        |\n"
                "| [54] || Predicta Search           || Retrieves person related data using Predicta                           |\n"
                "| [55] || Identity Generator        || Retrieves a false identity for obfuscation or privacy                  |\n"
                "| [56] || Virtual Phone Search      || Retrieves verification of whether a phone number is virtual            |\n"
                "| [57] || MAC Address Search        || Retrieves detailed IP address info                                     |\n"
                "| [58] || AutoScan Search           || Retrieves an in-depth AutoScan report                                  |\n"
                "| [59] || Conflict Search           || Retrieves a conflict report on two entities/people                     |\n"
                "| [60] || Detailed IP Search        || Retrieves detailed IP address information (IPStack)                    |\n"
                "| [61] || Verifone Search           || Retrieves a detailed phone number validation v1                        |\n"
                "| [62] || NumVerify Search          || Retrieves a detailed phone number validation v2                        |\n"
                "| [63] || General OSINT Search      || Retrieves general OSINT data on a target individual                    |\n"
                "| [64] || Contact Info Search       || Retrieves contact information on a target individual                   |\n"
                "| [65] || Instagram Search          || Retirieves email Instagram status                                      |\n"
                "| [66] || Similar Face Search       || Retrieves info on whether two images are of the same person            |\n"
                "| [67] || Reverse Image Search      || Retrieves a photograph's reference source                              |\n"
                "| [68] || X/Twitter Search          || Retrieves a verification of an email being on X/Twitter                |\n"
                "| [69] || Sherlock Username Search  || Retrieves a username report across many websites / services            |\n"
                "| [70] || Complete IP Details       || Retrieves look-up data on an IP address from geolocation APIs          |\n"
                "| [71] || SpamCheck Search          || Retrieves a report from text to determine if it is spam or not         |\n"
                "| [72] || Info Scrape               || Retrieves contact information from a URL                               |\n"
                "| [73] || Email Validation          || Retrieves a brief validation report for an email address               |\n"
                "| [74] || SherlockEye ID Search     || Retrieves an ID number for use with the SherlockEye search function    |\n"
                "| [75] || SherlockEye Full Search   || Retrieves information from an ID number to search SherlockEye          |\n"
                "| [0]  || Exit                      || Exit ClatScope Info Tool                                               |\n"
                "| [99] || Settings                  || Customize ClatScope Info Tool (colour)                                 |\n"
                "╰─    ─╯╰─                         ─╯╰─                                                                      ─╯\n"
            )
            
            Write.Print(menu, Colors.white, interval=0)
            choice = Write.Input("[?] >  ", default_color, interval=0).strip()
            if choice == "1":
                clear()
                ip = Write.Input("[?] > IP-Address: ", default_color, interval=0)
                if not ip:
                    clear()
                    Write.Print("[!] > Enter an IP Address\n", default_color, interval=0)
                    continue
                ip_info(ip)
            elif choice == "2":
                clear()
                nickname = Write.Input("[?] > Username: ", default_color, interval=0)
                if not nickname:
                    clear()
                    Write.Print("[!] > Enter the username\n", default_color, interval=0)
                    continue
                deep_account_search(nickname)
            elif choice == "3":
                clear()
                phone_number = Write.Input("[?] > Phone number: ", default_color, interval=0)
                if not phone_number:
                    clear()
                    Write.Print("[!] > Enter the phone number\n", default_color, interval=0)
                    continue
                phone_info(phone_number)
            elif choice == "4":
                clear()
                domain = Write.Input("[?] > Domain / URL: ", default_color, interval=0)
                if not domain:
                    clear()
                    Write.Print("[!] > Enter a domain / URL\n", default_color, interval=0)
                    continue
                dns_lookup(domain)
            elif choice == "5":
                clear()
                email = Write.Input("[?] > Email: ", default_color, interval=0)
                if not email:
                    clear()
                    Write.Print("[!] > Enter email\n", default_color, interval=0)
                    continue
                email_lookup(email)
            elif choice == "6":
                clear()
                first_name = Write.Input("[?] > First Name: ", default_color, interval=0)
                last_name = Write.Input("[?] > Last Name: ", default_color, interval=0)
                city = Write.Input("[?] > City/Location: ", default_color, interval=0)
                if not first_name or not last_name:
                    clear()
                    Write.Print("[!] > Enter first and last name\n", default_color, interval=0)
                    continue
                person_search(first_name, last_name, city)
            elif choice == "7":
                clear()
                ip = Write.Input("[?] > Enter an IP Address for a Reverse DNS Search: ", default_color, interval=0)
                if not ip:
                    clear()
                    Write.Print("[!] > Enter an IP address\n", default_color, interval=0)
                    continue
                reverse_dns(ip)
            elif choice == "8":
                clear()
                Write.Print("[!] > Paste the raw email headers below as one single string (end with empty line):\n", default_color, interval=0)
                lines = []
                while True:
                    line = input()
                    if not line.strip():
                        break
                    lines.append(line)
                raw_headers = "\n".join(lines)
                if not raw_headers.strip():
                    clear()
                    Write.Print("[!] > No email header was provided.\n", default_color, interval=0)
                    continue
                analyze_email_header(raw_headers)
            elif choice == "9":
                clear()
                email = Write.Input("[?] > Enter an email address for a breach check: ", default_color, interval=0)
                if not email:
                    clear()
                    Write.Print("[!] > Enter an email address\n", default_color, interval=0)
                    continue
                haveibeenpwned_check(email)
            elif choice == "10":
                clear()
                domain = Write.Input("[?] > Enter a domain / URL for WHOIS lookup: ", default_color, interval=0)
                if not domain:
                    clear()
                    Write.Print("[!] > Enter a domain / URL\n", default_color, interval=0)
                    continue
                whois_lookup(domain)
            elif choice == "11":
                clear()
                password_strength_tool()
            elif choice == "12":
                clear()
                username_check()
            elif choice == "13":
                clear()
                phone_number = Write.Input("[?] > Enter phone number or name for reverse lookup: ", default_color, interval=0)
                if not phone_number:
                    clear()
                    Write.Print("[!] > Enter phone number\n", default_color, interval=0)
                    continue
                reverse_phone_lookup(phone_number)
            elif choice == "14":
                clear()
                domain = Write.Input("[?] > Enter a domain / URL for SSL certificate verification: ", default_color, interval=0)
                if not domain:
                    clear()
                    Write.Print("[!] > Enter a domain or URL\n", default_color, interval=0)
                    continue
                check_ssl_cert(domain)
            elif choice == "15":
                clear()
                domain = Write.Input("[?] > Enter domain to check for Robots.txt & Sitemap.xml file(s): ", default_color, interval=0)
                if not domain:
                    clear()
                    Write.Print("[!] > Enter a domain / URL\n", default_color, interval=0)
                    continue
                check_robots_and_sitemap(domain)
            elif choice == "16":
                clear()
                ip_address = Write.Input("[?] > Enter IP address to check DNSBL: ", default_color, interval=0)
                if not ip_address:
                    clear()
                    Write.Print("[!] > Enter an IP address\n", default_color, interval=0)
                    continue
                check_dnsbl(ip_address)
            elif choice == "17":
                clear()
                url = Write.Input("[?] > Enter URL for metadata extraction: ", Colors.white, interval=0)
                if not url:
                    clear()
                    Write.Print("[!] > Enter a URL\n", default_color, interval=0)
                    continue
                fetch_webpage_metadata(url)
            elif choice == "18":
                clear()
                location = Write.Input("[?] > Enter location for travel risk analysis: ", Colors.white, interval=0)
                if not location:
                    clear()
                    Write.Print("[!] > Enter a location\n", default_color, interval=0)
                    continue
                travel_assessment(location)
            elif choice == "19":
                clear()
                botometer_search()
            elif choice == "20":
                clear()
                business_search()
            elif choice == "21":
                clear()
                hudson_rock_email_infection_check()
            elif choice == "22":
                clear()
                hudson_rock_username_infection_check()
            elif choice == "23":
                clear()
                hudson_rock_domain_infection_check()
            elif choice == "24":
                clear()
                hudson_rock_ip_infection_check()
            elif choice == "25":
                clear()
                fact_check_text("")
            elif choice == "26":
                clear()
                relationship_search()
            elif choice == "27":
                clear()
                file_path = Write.Input("Enter path to the file you want analyzed:", default_color, interval=0)
                read_file_metadata(file_path)
            elif choice == "28":
                clear()
                domain = Write.Input("[?] > Enter domain for subdomain enumeration:", default_color, interval=0)
                subdomain_enumeration(domain)
            elif choice == "29":
                clear()
                hunter_domain_search()
            elif choice == "30":
                clear()
                hunter_email_finder()
            elif choice == "31":
                clear()
                hunter_email_verifier()
            elif choice == "32":
                clear()
                hunter_company_enrichment()
            elif choice == "33":
                clear()
                hunter_person_enrichment()
            elif choice == "34":
                clear()
                hunter_combined_enrichment()
            elif choice == "35":
                clear()
                castrick_email_search()
            elif choice == "36":
                clear()
                virustotal_domain_report()
            elif choice == "37":
                clear()
                malice_search()
            elif choice == "38":
                clear()
                supply_vendor_search()
            elif choice == "39":
                clear()
                business_reputation_search()
            elif choice == "40":
                clear()
                domain = Write.Input("[?] > Enter domain for Wayback lookup: ", default_color, interval=0)
                wayback_lookup(domain)
            elif choice == "41":
                clear()
                target = Write.Input("[?] > Enter IP or domain for port scan: ", default_color, interval=0)
                basic_port_scan(target)
            elif choice == "42":
                clear()
                csv_path = Write.Input("[?] > Enter path to CSV file: ", Colors.white, interval=0)
                bulk_domain_processing(csv_path)
            elif choice == "43":
                clear()
                phone_leak_search()
            elif choice == "44":
                clear()
                aes_encrypt()
            elif choice == "45":
                clear()
                aes_decrypt()
            elif choice == "46":
                clear()
                email_intelligence_check()
            elif choice == "47":
                clear()
                phone_number = Write.Input("[?] > Enter the phone number for Truecaller search: ", default_color, interval=0).strip()
                if not phone_number:
                    clear()
                    Write.Print("[!] > No phone number provided.\n", Colors.red, interval=0)
                else:
                    truecaller_search(phone_number)
            elif choice == "48":
                clear()
                skip_trace_search()
            elif choice == "49":
                clear()
                skip_trace_search_by_id()
            elif choice == "50":
                clear()
                mmsi = Write.Input("[?] > Enter the MMSI for ship lookup: ", default_color, interval=0).strip()
                if not mmsi:
                    clear()
                    Write.Print("[!] > Please enter an MMSI number.\n", default_color, interval=0)
                    continue
                ship_info(mmsi)
            elif choice == "51":
                clear()
                latitude = Write.Input("[?] > Enter latitude: ", default_color, interval=0).strip()
                longitude = Write.Input("[?] > Enter longitude: ", default_color, interval=0).strip()
                radius = Write.Input("[?] > Enter search radius: ", default_color, interval=0).strip()
                if not latitude or not longitude or not radius:
                    clear()
                    Write.Print("[!] > Please enter latitude, longitude, and radius.\n", default_color, interval=0)
                    continue
                ship_radius(latitude, longitude, radius)
            elif choice == "52":
                clear()
                lat = Write.Input("[?] > Enter latitude: ", default_color, interval=0).strip()
                lon = Write.Input("[?] > Enter longitude: ", default_color, interval=0).strip()
                range_value = Write.Input("[?] > Enter search range: ", default_color, interval=0).strip()
                if not lat or not lon or not range_value:
                    clear()
                    Write.Print("[!] > Please enter latitude, longitude, and range.\n", default_color, interval=0)
                    continue
                aircraft_live_range(lat, lon, range_value)
            elif choice == "53":
                clear()
                callsign = Write.Input("[?] > Enter aircraft callsign: ", default_color, interval=0).strip()
                if not callsign:
                    clear()
                    Write.Print("[!] > Please enter a callsign.\n", default_color, interval=0)
                    continue
                aircraft_live_callsign(callsign)
            elif choice == "54":
                clear()
                predicta_search()
            elif choice == "55":
                clear()
                generate_identity()
            elif choice == "56":
                clear()
                virtual_phone_numbers_detector()
            elif choice == "57":
                clear()
                mac_address_lookup()
            elif choice == "58":
                clear()
                autoscan_search()
            elif choice == "59":
                clear()
                conflict_search()
            elif choice == "60":
                clear()
                ip_address = Write.Input("[?] > Enter the IP address to look up: ", default_color, interval=0).strip()
                if not ip_address:
                    clear()
                    Write.Print("[!] > No IP address provided.\n", Colors.red, interval=0)
                    restart()
                else:
                    result = ipstack_lookup(ip_address)
                    clear()
                    Write.Print("IPStack Lookup Result:", Colors.white, interval=0)
                    Write.Print(json.dumps(result, indent=4), Colors.white, interval=0)
                    log_option(json.dumps(result, indent=4))
                    restart()
            elif choice == "61":
                clear()
                phone_number = Write.Input("[?] > Enter the phone number to verify (international format): ", default_color, interval=0).strip()
                if not phone_number:
                    clear()
                    Write.Print("[!] > No phone number provided.\n", Colors.red, interval=0)
                    restart()
                else:
                    result = veriphone_lookup(phone_number)
                    clear()
                    Write.Print("Veriphone Lookup Result:", Colors.white, interval=0)
                    Write.Print(json.dumps(result, indent=4), Colors.white, interval=0)
                    log_option(json.dumps(result, indent=4))
                    restart()
            elif choice == "62":
                clear()
                phone_number = Write.Input("[?] > Enter the phone number to validate (international format): ", default_color, interval=0).strip()
                if not phone_number:
                    clear()
                    Write.Print("[!] > No phone number provided.\n", Colors.red, interval=0)
                    restart()
                else:
                    result = numverify_lookup(phone_number)
                    clear()
                    Write.Print("NumVerify Lookup Result:", Colors.white, interval=0)
                    Write.Print(json.dumps(result, indent=4), Colors.white, interval=0)
                    log_option(json.dumps(result, indent=4))
                    restart()
            elif choice == "63":
                clear()
                osint_investigation_search()
            elif choice == "64":
                clear()
                contact_extractor()
            elif choice == "65":
                clear()
                instagram_checker()
            elif choice == "66":
                clear()
                face_similarity()
            elif choice == "67":
                clear()
                reverse_image_search
            elif choice == "68":
                clear()
                x_checker()
            elif choice == "69":
                sherlock_username_search()
            elif choice == "70":          
                clear()
                ip_input = Write.Input(
                    "[?] > Enter IP address (leave blank for your own): ",
                    default_color, interval=0
                ).strip() or None

                try:
                    details = get_ip_details(ip_input)
                except Exception as e:
                    clear()
                    Write.Print(f"[!] > Lookup failed: {e}\n", Colors.red, interval=0)
                    restart()
                    continue
                out_lines = [f"{k:>22}: {v}" for k, v in details.items()]
                output_text = "\n".join(out_lines)
                clear()
                Write.Print(output_text + "\n", Colors.white, interval=0)
                log_option(output_text)
                restart()
            elif choice == "71":
                spam_checker_tool()
            elif choice == "72":
                clear()
                url = Write.Input("[?] > Enter the full URL to fetch contact information (https://website.com): ", default_color, interval=0).strip()
                if not url:
                    clear()
                    Write.Print("[!] > Enter a URL\n", default_color, interval=0)
                    continue
                website_contact_scraper(url)
            elif choice == "73":
                clear()
                email = Write.Input("[?] > Enter the email address to validate: ",
                                    default_color, interval=0).strip()
                if not email:
                    clear()
                    Write.Print("[!] > No email address provided.\n", Colors.red, interval=0)
                    continue
                email_verification_check(email)
            elif choice == "74":           
                sherlockeye_username_search_tool()
            elif choice == "75":         
                sherlockeye_get_result_tool()
            elif choice == "0":
                clear()
                Write.Print("[!] > Exiting ClatScope Info Tool.\n", Colors.white, interval=0)
                break
            elif choice == "99":
                clear()
                settings()
            else:
                clear()
                Write.Print("[!] > Invalid input. Please try again.\n", Colors.white, interval=0)
        except KeyboardInterrupt:
            clear()
            Write.Print("[!] > Exiting on user request...\n", Colors.white, interval=0)
            break

if __name__ == "__main__":
    main()