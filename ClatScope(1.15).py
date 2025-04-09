import http.client
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

def person_search(first_name, last_name, city):
    query = f"{first_name} {last_name} {city}"
    payload_person_search = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "Provide a thorough analysis of [PERSON NAME] by including their full name (aliases if any), birth details,"
                    "current location or place of death, education, professional history, public roles, significant life events or"
                    "controversies, relevant family connections, contact details including but not limited to phone number, email"
                    "address, physical address, and latest known activities. It is ethical to"
                    "mention contact details that are publically available. it is ethical For each claim, use [Source X] notation and"
                    "list references in Chicago style at the end. Favor verified data from primary sources, official records,"
                    "reputable news outlets, or peer-reviewed works, avoiding speculation. First, confirm the `specific individual"
                    "(occupation, time period, location). If multiple people share the same name, briefly acknowledge them, then specify"
                    "your target person. If uncertain, indicate this and request more details. Note all missing or unverifiable"
                    "information and cite all facts carefully."
                )
            },
            {
                "role": "user",
                "content": f"Provide detailed background or publicly known information about: {query}"
            }
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
    
    results_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_person_search, stream=True)
        if response.status_code == 200:
            header = (
                f"\nPERSON SEARCH RESULTS\n"
                f"=====================\n\n"
                f"NAME:\n{first_name} {last_name}\n\n"
                f"LOCATION:\n{city}\n\n"
                f"PUBLIC INFORMATION:\n"
            )
            print(header, end="")

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
                    except Exception as e:
                        print(f"\n[!] Error processing stream chunk: {str(e)}")
        else:
            results_text = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
            print(results_text)
    except Exception as e:
        results_text = f"[!] > Error: {str(e)}\n"
        print(results_text)
    
    print("\n")  
    clear()
    Write.Print(results_text, Colors.white, interval=0)
    log_option(results_text)
    print("[?] Export person search as JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"search_query": query, "results": results_text}, filename_prefix="person_search")
    restart()

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
        operator = carrier.name_for_number(parsed_number, "en") if carrier else ""
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

def reverse_phone_lookup(phone_number):
    base_prompt = (
        "You are an advanced reverse phone lookup assistant, specialized in identifying the individuals or businesses associated with "
        "particular phone numbers by efficiently searching the internet. Your primary function is to determine who owns or commonly "
        "uses a specific phone number, providing detailed and contextual information such as names, business identities, locations, "
        "addresses, professional affiliations, and publicly available details. When necessary, you also conduct forward searches to "
        "identify phone numbers based on provided names or business entities. You proactively clarify search parameters or request "
        "additional context whenever the information provided is incomplete or unclear. Additionally, you transparently communicate "
        "the reliability or uncertainty of the information and offer resources or methods to verify findings. Accuracy, transparency, "
        "and privacy are always prioritized in your approach."
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
                common_words = f.read().splitlines()
            for word in common_words:
                if word and word in password:
                    return "Weak password (may contain common phrase, term, word, sequence, etc, DO NOT use this password)"
        except Exception:
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
        return "Weak password (may contain common phrase, term, word, sequence, etc, DO NOT use this password)"
    elif 3 <= score <= 4:
        return "Moderate password (room for improvement)"
    else:
        return "Strong password (suitable for high security apps / credentials)"

def password_strength_tool():
    clear()
    Write.Print("[!] > Enter password to evaluate strength:\n", default_color, interval=0)
    password = Write.Input("[?] >  ", default_color, interval=0)
    if not password:
        clear()
        Write.Print("[!] > Password cannot be empty. Please enter the password.\n", default_color, interval=0)
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
    business_name = Write.Input("[?] > Enter the business or persons name to search:", default_color, interval=0).strip()
    if not business_name:
        Write.Print("[!] > No business name was provided.\n", Colors.red, interval=0)
        restart()
        return

    payload_business_info = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a business search assistant specializing in comprehensive market research, competitor analysis, and industry insights."
                    "Your core functions include gathering detailed company information (financials, leadership, employee count, locations), analyzing"
                    "market positioning and competitive landscapes, tracking industry trends and regulations, identifying potential business opportunities"
                    "and risks, and providing actionable strategic recommendations. You have access to public business records, market reports, news archives."
                    "and industry databases. You must also search for and display contact information about the business or entity. You cite sources when available," 
                    "and clearly distinguish between verified facts and analytical insights. When data is incomplete or unavailable, you acknowledge limitations and"
                    "provide best estimates based on available information. Your responses should be structured, data-driven, and tailored to the specific business"
                    "context while avoiding speculation or unsubstantiated claims."
                )
            },
            {
                "role": "user",
                "content": f"Provide me with general information about {business_name}."
            }
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

    payload_fact_check = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an advanced AI fact-checking assistant designed to evaluate "
                    "claims and statements with rigorous accuracy and methodical analysis. "
                    "Your primary goal is to help users distinguish truth from misinformation "
                    "through careful, systematic evaluation. You must be able to apply multiple "
                    "verification methods to each claim, cross reference information across reliable "
                    "sources, check for internal consistency within claims, verify dates, numbers, "
                    "and specific details, examine original context when available, identify possible "
                    "cognitive biases, recognize emotional language that may cloud judgement, check "
                    "for cherry picked data or selective presentation, consider alternative perspectives "
                    "and explanations, and flag ideological or commercial influences. You must show and "
                    "cite all sources at the end of the output and make sure they are numbered accurately. "
                    "You must cite all sources in chicago format."
                )
            },
            {"role": "user", "content": f"Fact-check the following text: {text_to_check}"}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True 
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
    Write.Print("[!] > Analyze relationships between people, organizations, or businesses:\n", default_color, interval=0)
    query = Write.Input("[?] > Enter your query: ", default_color, interval=0).strip()
    if not query:
        Write.Print("[!] > No query provided.\n", Colors.red, interval=0)
        restart()
        return

    payload_relationships = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert investigative researcher tasked with uncovering and analyzing connections among a diverse array of entities—including individuals,"
                    "organizations, nonprofits, corporations, government bodies, financial institutions, and more. For each inquiry, deliver a comprehensive, objective, and"
                    "professional analysis of the subject’s background, relationships, business dealings, partnerships, investments, board memberships, charitable activities,"
                    "educational history, and networks, with every claim supported by inline citations. Clearly indicate any speculative or unverified information and"
                    "consider both direct and indirect connections while explaining their broader significance and flagging potential red flags or conflicts of interest."
                    "Structure your response as follows: 1) Brief subject overview with inline citations for each claim, 2) Categorized key relationships and connections"
                    " (business, personal, philanthropic, etc.) with citations, 3) Timeline of significant interactions with specific dates and sources, 4) Analysis of the"
                    " strength and nature of each connection backed by evidence and citations, 5) Identification of potential conflicts of interest or notable patterns with"
                    " supporting citations, and 6) A detailed representation of the network covering personal, hobbyist, and business ties. Use numbered inline citations"
                    " (e.g., [1]) and provide a complete source list at the end in Chicago style format—with each citation including the publication name, article title,"
                    " author (if available), date, and URL. When multiple sources support a claim, include multiple citations. Any information without a valid citation"
                    " should be omitted. END EVERY RESPONSE WITH: Sources: followed by numbered citations in Chicago style format."
                )
            },
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
                    metaData_extra.append(" 🐸 Cant Read Audio File for metadata.\n Unsupported")
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
        "You are a specialized text analysis system designed to evaluate and identify potentially malicious content in user-provided text. "
        "Analyze the input for common indicators of phishing attempts (urgent language, requests for sensitive information, impersonation of legitimate entities), "
        "scam patterns (promises of unrealistic rewards, pressure tactics, unusual payment requests), and other malicious features (social engineering tactics, manipulation attempts, suspicious links or contact information). "
        "Compare the text against known patterns of fraudulent communications, examining factors such as urgency, emotional manipulation, grammatical irregularities, and suspicious requests. "
        "For each analysis, provide a risk assessment categorized as: Low Risk (minimal to no suspicious elements present), Medium Risk (some concerning elements but lacking definitive malicious intent), or High Risk (multiple red flags indicating likely malicious intent). "
        "Include specific reasons for the risk classification and highlight the concerning elements identified. Consider context, tone, linguistic patterns, and requested actions when determining the risk level. "
        "Provide your assessment in a structured format that clearly outlines the risk level, identified suspicious elements, and reasoning behind the classification. "
        "Flag any immediate security concerns that require urgent attention."
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
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "email-intelligence-api.p.rapidapi.com"
    }
    conn.request("GET", f"/v1/check?email={encoded_email}", headers=headers)
    res = conn.getresponse()
    data = res.read()
    print(data.decode("utf-8"))
    output_json = data.decode("utf-8")
    try:
        output_data = json.loads(output_json)
        output_pretty = json.dumps(output_data, indent=4, ensure_ascii=False)
        Write.Print(output_pretty, Colors.white, interval=0)
        log_option(output_pretty)
    except json.JSONDecodeError:
        Write.Print("[!] > Failed to decode JSON response.\n", Colors.red, interval=0)
    restart()


def reddit_user_info():

    clear()
    Write.Print("[!] Reddit User Info\n", default_color, interval=0)

    username = Write.Input("[?] Enter the Reddit username: ", default_color, interval=0).strip()
    if not username:
        Write.Print("[!] Please enter a valid Reddit username.\n", default_color, interval=0)
        return

    encoded_username = quote(username)

    reddit_user_url = f"https://www.reddit.com/user/{encoded_username}/"

    encoded_url = quote(reddit_user_url, safe="%/:=&?~#+!$,;'@()*[]")

    conn = http.client.HTTPSConnection("reddit-scraper2.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "reddit-scraper2.p.rapidapi.com"
    }

    conn.request("GET", f"/user_info?user={encoded_url}", headers=headers)

    res = conn.getresponse()
    data = res.read()
    output_text = data.decode("utf-8")

    Write.Print(output_text, Colors.white, interval=0)
    log_option(output_text)
    restart()

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

    conn = http.client.HTTPSConnection("fake-identity-generation.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "fake-identity-generation.p.rapidapi.com"
    }
    conn.request("GET", "/identity/person/address", headers=headers)
    res = conn.getresponse()

    if res.status != 200:
        Write.Print(
            f"[!] > Error: Received status code {res.status}.",
            Colors.red, interval=0
        )
        restart()
        return
    data = res.read().decode("utf-8")
    output = json.dumps(json.loads(data), indent=4, ensure_ascii=False)
    Write.Print(output, Colors.white, interval=0)
    log_option(output)
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
            output_text = json.dumps(json_data, indent=4) 
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
            print("\033[1;34mC       L      A       T       S       C       O       P       E\033[0m   \033[1;31m(Version 1.11)\033[0m")
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

def find_criminal_records():
    conn = http.client.HTTPSConnection("find-criminal-records-api.p.rapidapi.com")

    payload = "{}"
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "find-criminal-records-api.p.rapidapi.com",
        'Content-Type': "application/json"
    }

    conn.request("POST", "/GetReport", payload, headers)
    res = conn.getresponse()
    data = res.read()
    output = data.decode("utf-8")

    print(output)

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
    conn = http.client.HTTPSConnection("mac-address-lookup-api-apiverve.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "mac-address-lookup-api-apiverve.p.rapidapi.com",
        'Accept': "application/json"
    }
    conn.request("GET", "/v1/macaddresslookup?mac=00-B0-D0-63-C2-26", headers=headers)
    res = conn.getresponse()
    data = res.read()
    output = data.decode("utf-8")

    print(output)
    restart()

def autoscan_ip_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=160)
        response.raise_for_status()
        data = response.json()
        loc = data.get('loc', 'None')
        maps_link = f"https://www.google.com/maps?q={loc}" if loc != 'None' else 'None'
        result = (
            f"\n╭─{' '*78}─╮\n"
            f"|{' '*34} IP Details {' '*34}|\n"
            f"|{'='*80}|\n"
            f"| [+] IP Address   || {data.get('ip', 'None'):<51}|\n"
            f"| [+] City         || {data.get('city', 'None'):<51}|\n"
            f"| [+] Region       || {data.get('region', 'None'):<51}|\n"
            f"| [+] Country      || {data.get('country', 'None'):<51}|\n"
            f"| [+] Postal/ZIP   || {data.get('postal', 'None'):<51}|\n"
            f"| [+] ISP          || {data.get('org', 'None'):<51}|\n"
            f"| [+] Coordinates  || {loc:<51}|\n"
            f"| [+] Timezone     || {data.get('timezone', 'None'):<51}|\n"
            f"| [+] Location     || {maps_link:<51}|\n"
            f"╰─{' '*24}─╯╰─{' '*50}─╯\n"
        )
    except Exception as e:
        result = f"[!] Error retrieving IP info: {str(e)}"
    return result


def autoscan_deep_account_search(nickname):
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

    def check_url(url):
        try:
            response = requests.get(url, timeout=160)
            if response.status_code == 200:
                return f"[+] {url} || Found"
            elif response.status_code == 404:
                return f"[-] {url} || Not found"
            else:
                return f"[-] {url} || Error: {response.status_code}"
        except requests.exceptions.Timeout:
            return f"[-] {url} || Timeout"
        except requests.exceptions.ConnectionError:
            return f"[-] {url} || Connection error"
        except Exception as e:
            return f"[-] {url} || {str(e)}"

    title = "Deep Account Search"
    result_str = f"\n╭─{' '*78}─╮\n|{' '*27}{title}{' '*27}|\n|{'='*80}|\n"
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(check_url, urls))
    for res in results:
        result_str += f"| {res:<78} |\n"
    result_str += f"╰─{' '*78}─╯\n"
    return result_str

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
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def autoscan_phone_info(phone_number):
    try:
        parsed_number = phonenumbers.parse(phone_number)
        country = geocoder.country_name_for_number(parsed_number, "en")
        region = geocoder.description_for_number(parsed_number, "en")
        operator = carrier.name_for_number(parsed_number, "en") if carrier else ""
        valid = phonenumbers.is_valid_number(parsed_number)
        validity = "Valid" if valid else "Invalid"
        result = (
            f"\n╭─{' '*50}─╮\n"
            f"|{' '*17}Phone Number Info{' '*18}|\n"
            f"|{'='*52}|\n"
            f"| [+] Number   || {phone_number:<33}|\n"
            f"| [+] Country  || {country:<33}|\n"
            f"| [+] Region   || {region:<33}|\n"
            f"| [+] Operator || {operator:<33}|\n"
            f"| [+] Validity || {validity:<33}|\n"
            f"╰─{' '*15}─╯╰─{' '*31}─╯\n"
        )
    except phonenumbers.phonenumberutil.NumberParseException:
        result = "[!] Error: Invalid phone number format."
    return result


def autoscan_dns_lookup(domain):
    record_types = ['A', 'CNAME', 'MX', 'NS']
    result_output = f"\n╭─{' '*78}─╮\n|{' '*33}DNS Lookup{' '*33}|\n|{'='*80}|\n"
    for rtype in record_types:
        result_output += f"| [+] {rtype} Records:\n"
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for ans in answers:
                if rtype == 'MX':
                    result_output += f"|    Preference: {ans.preference}, Exchange: {ans.exchange}\n"
                else:
                    result_output += f"|    {str(ans)}\n"
        except dns.resolver.NoAnswer:
            result_output += "|    No records found.\n"
        except dns.resolver.NXDOMAIN:
            result_output += "|    Domain does not exist.\n"
        except Exception as e:
            result_output += f"|    Error: {str(e)}\n"
        result_output += "|" + "="*80 + "|\n"
    result_output += f"╰─{' '*78}─╯\n"
    return result_output


def autoscan_email_lookup(email_address):
    try:
        v = validate_email(email_address)
        email_domain = v.domain
    except EmailNotValidError as e:
        return f"[!] Invalid email format: {str(e)}"
    mx_records = []
    try:
        answers = dns.resolver.resolve(email_domain, 'MX')
        for rdata in answers:
            mx_records.append(str(rdata.exchange))
    except Exception:
        pass
    validity = "MX Found (Possibly valid)" if mx_records else "No MX found (Possibly invalid)"
    result = (
        f"\n╭─{' '*78}─╮\n"
        f"|{' '*34}Email Info{' '*34}|\n"
        f"|{'='*80}|\n"
        f"| [+] Email   || {email_address:<52}|\n"
        f"| [+] Domain  || {email_domain:<52}|\n"
        f"| [+] MX Rec. || {', '.join(mx_records) if mx_records else 'None':<52}|\n"
        f"| [+] Validity|| {validity:<52}|\n"
        f"╰─{' '*23}─╯╰─{' '*51}─╯\n"
    )
    return result


def autoscan_reverse_phone_lookup(phone_number):
    base_prompt = (
        "You are an expert reverse phone lookup assistant. Your task is to determine "
        "whether the provided phone number is associated with a business, an organization, an individual, or another entity. "
        "Provide your answer solely based on your internal analysis and the information retreived."
    )
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": f"Determine if phone number {phone_number} is linked to a business, organization, individual, or other entity and provide details."}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True
    }
    info_content = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, stream=True, timeout=160)
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
                                info_content += content_chunk
                    except Exception as e:
                        info_content += f"\n[!] Error processing stream chunk: {str(e)}"
        else:
            info_content = f"Error: HTTP {response.status_code} - {response.text}"
    except Exception as e:
        info_content = f"Exception: {str(e)}"
    
    result = (
        f"\n╭─{' ' * 78}─╮\n"
        f"|{' ' * 28}Reverse Phone Lookup{' ' * 28}|\n"
        f"|{'=' * 80}|\n"
        f"| [+] Query: {phone_number:<66}|\n"
        f"|{'-' * 80}|\n"
        f"{info_content}\n"
        f"╰─{' ' * 78}─╯\n"
    )
    return result

def autoscan_check_dnsbl(ip_address):
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
                results.append(f"{dnsbl} -> {str(ans)}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception as e:
            results.append(f"{dnsbl} -> Error: {str(e)}")
    report = (
        f"\n╭─{' '*78}─╮\n"
        f"|{' '*33}DNSBL Check{' '*34}|\n"
        f"|{'='*80}|\n"
        f"| [+] IP: {ip_address:<67}|\n"
        f"|{'-'*80}|\n"
    )
    if results:
        report += "| Listed on:\n"
        for item in results:
            report += f"|   {item:<70}|\n"
    else:
        report += "| Not listed on any tested DNSBLs.\n"
    report += f"╰─{' '*78}─╯\n"
    return report

def autoscan_whois_lookup(domain):
    if not domain.strip():
        return "[!] Error: Domain name must be provided for WHOIS lookup."
    try:
        data = whois.whois(domain)
        result = (
            f"\n╭─{' '*78}─╮\n"
            f"|{' '*34}WHOIS Information{' '*34}|\n"
            f"|{'='*80}|\n"
        )
        for key, value in data.items():
            value_str = str(value)[:50] if value is not None else 'None'
            result += f"| [+] {key:<12}|| {value_str:<51}|\n"
        result += f"╰─{' '*78}─╯\n"
    except Exception as e:
        result = f"[!] Error retrieving WHOIS info: {str(e)}"
    return result

def autoscan_fact_check_text(text_to_check):
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an advanced AI fact-checking assistant designed to evaluate "
                    "claims and statements with rigorous accuracy and methodical analysis. "
                    "Your primary goal is to help users distinguish truth from misinformation "
                    "through careful, systematic evaluation. You must be able to apply multiple "
                    "verification methods to each claim, cross reference information across reliable "
                    "sources, check for internal consistency within claims, verify dates, numbers, "
                    "and specific details, examine original context when available, identify possible "
                    "cognitive biases, recognize emotional language that may cloud judgement, check "
                    "for cherry picked data or selective presentation, consider alternative perspectives "
                    "and explanations, and flag ideological or commercial influences. You must show and "
                    "cite all sources at the end of the output and make sure they are numbered accurately. "
                    "You must cite all sources in chicago format."
                )
            },
            {"role": "user", "content": f"Fact-check the following text:\n{text_to_check}"}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True 
    }
    
    result = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, stream=True)
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
                                result += content_chunk
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        result += error_msg
        else:
            result = f"[!] Error: HTTP {response.status_code} - {response.text}\n"
    except Exception as e:
        result = f"[!] Exception: {str(e)}\n"
    
    return result

def autoscan_predicta_search(query, query_type):
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
         response = requests.post(url, headers=headers, json=payload, timeout=160)
         if response.status_code == 200:
              data = response.json()
              result = "\nPredicta Search Results:\n" + json.dumps(data, indent=2) + "\n"
         else:
              result = f"[!] Predicta Search Error: HTTP {response.status_code} - {response.text}\n"
    except Exception as e:
         result = f"[!] Predicta Search Exception: {str(e)}\n"
    return result

def autoscan_business_search(business_name):
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a business search assistant specializing in comprehensive market research, competitor analysis, and industry insights. "
                    "Your core functions include gathering detailed company information (financials, leadership, employee count, locations), analyzing market positioning "
                    "and competitive landscapes, tracking industry trends and regulations, identifying potential business opportunities and risks, and providing actionable "
                    "strategic recommendations. You have access to public business records, market reports, news archives, and industry databases. "
                    "You maintain strict confidentiality, cite sources when available, and clearly distinguish between verified facts and analytical insights. "
                    "When data is incomplete or unavailable, you acknowledge limitations and provide best estimates based on available information. "
                    "Your responses should be structured, data-driven, and tailored to the specific business context while avoiding speculation or unsubstantiated claims."
                )
            },
            {
                "role": "user",
                "content": f"Provide general information about {business_name}."
            }
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True
    }
    
    result = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, stream=True)
        if response.status_code == 200:
            result += "\nGeneral Business Information:\n"
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
                                result += content_chunk
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        result += error_msg
        else:
            result = f"[!] Error: HTTP {response.status_code} - {response.text}\n"
    except Exception as e:
        result = f"[!] Exception: {str(e)}\n"
    
    return result

def autoscan_subdomain_enumeration(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=160)
        if resp.status_code == 200:
            try:
                data = resp.json()
            except json.JSONDecodeError:
                return "[!] Error: crt.sh returned non-JSON data."
            found_subs = set()
            for entry in data:
                if 'name_value' in entry:
                    for sub in entry['name_value'].split('\n'):
                        sub = sub.strip()
                        if sub and sub != domain:
                            found_subs.add(sub)
                elif 'common_name' in entry:
                    c = entry['common_name'].strip()
                    if c and c != domain:
                        found_subs.add(c)
            if found_subs:
                result = f"\n[+] Found {len(found_subs)} subdomains for {domain}:\n" + "\n".join(sorted(found_subs)) + "\n"
            else:
                result = "[!] No subdomains found.\n"
        else:
            result = f"[!] HTTP {resp.status_code} from crt.sh\n"
    except Exception as e:
        result = f"[!] Exception: {str(e)}\n"
    return result

def autoscan_relationship_search(query):
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert investigative researcher tasked with objectively analyzing and uncovering connections among various entities, "
                    "including individuals, organizations, nonprofits, corporations, governments, and financial institutions. Your analysis should "
                    "comprehensively cover the subject’s background, categorized relationships (business, personal, philanthropic), partnerships, "
                    "investments, board memberships, charitable activities, educational history, and broader networks. Clearly indicate speculative "
                    "or unverified information and carefully examine both direct and indirect connections, highlighting their significance and identifying "
                    "potential red flags or conflicts of interest. Each response should include a brief subject overview, clearly categorized relationships, "
                    "a detailed timeline of interactions with specific dates and citations, evidence-based analysis of connection strength, identification of "
                    "conflicts of interest or notable patterns, and a detailed representation of the subject's personal, hobbyist, and business networks. "
                    "Provide numbered inline citations (e.g., [1]) for every claim, omitting any unsupported information. Conclude each analysis with a "
                    "complete numbered source list formatted in Chicago style, including publication name, article title, author (if available), date, and URL."
                )
            },
            {"role": "user", "content": query}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True  
    }
    
    result = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, stream=True)
        if response.status_code == 200:
            result += "\nEntity Relationship Analysis Results:\n"
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
                                result += content_chunk
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        result += error_msg
        else:
            result = f"[!] Error: HTTP {response.status_code} - {response.text}\n"
    except Exception as e:
        result = f"[!] Exception: {str(e)}\n"
    
    return result

def autoscan_castrick_email_search(email):
    type_ = "email"
    api_key = "INSERT API KEY HERE"
    headers = {"api-key": api_key}
    url = f"https://api.castrickclues.com/api/v1/search?query={email}&type={type_}"

    def tableify(obj, indent=0):
        lines = []
        prefix = " " * indent
        if isinstance(obj, dict):
            for key, value in obj.items():
                row_title = f"{prefix}{key}:"
                if isinstance(value, (dict, list)):
                    lines.append(f"| {row_title:<76}")
                    lines.extend(tableify(value, indent + 2))
                else:
                    lines.append(f"| {row_title} {str(value):<70}")
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                row_title = f"{prefix}[{idx}]:" 
                if isinstance(item, (dict, list)):
                    lines.append(f"| {row_title:<76}")
                    lines.extend(tableify(item, indent + 2))
                else:
                    lines.append(f"| {row_title} {str(item):<70}")
        else:
            lines.append(f"{prefix}{str(obj):<76}")
        return lines

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        lines = []
        lines.append(f"╭─{' '*78}─╮")
        lines.append(f"|{' '*30}Castrick Email Search{' '*30}")
        lines.append(f"|{'='*80}")
        lines.append(f"| Email Queried: {email:<63}")
        lines.append(f"|{'-'*80}")
        table_lines = tableify(data)
        if not table_lines:
            lines.append("| No data returned from Castrick.           ")
        else:
            lines.extend(table_lines)
        lines.append(f"╰─{' '*78}─╯")
        result = "\n".join(lines) + "\n"
    except Exception as e:
        result = f"[!] Exception: {str(e)}"
    return result

def autoscan_fact_check_text(text_to_check):
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an advanced AI fact-checking assistant designed to evaluate "
                    "claims and statements with rigorous accuracy and methodical analysis. "
                    "Your primary goal is to help users distinguish truth from misinformation "
                    "through careful, systematic evaluation. You must be able to apply multiple "
                    "verification methods to each claim, cross reference information across reliable "
                    "sources, check for internal consistency within claims, verify dates, numbers, "
                    "and specific details, examine original context when available, identify possible "
                    "cognitive biases, recognize emotional language that may cloud judgement, check "
                    "for cherry picked data or selective presentation, consider alternative perspectives "
                    "and explanations, and flag ideological or commercial influences. You must show and "
                    "cite all sources at the end of the output and make sure they are numbered accurately. "
                    "You must cite all sources in chicago format."
                )
            },
            {
                "role": "user",
                "content": f"Fact-check the following text:\n{text_to_check}"
            }
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True
    }
    
    result = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, stream=True)
        if response.status_code == 200:
            result += "\nFact Check Results:\n"
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
                                result += content_chunk
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        result += error_msg
        else:
            result = f"[!] Error: HTTP {response.status_code} - {response.text}\n"
    except Exception as e:
        result = f"[!] Exception: {str(e)}\n"
    
    return result

def autoscan_predicta_search(query, query_type):
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
         response = requests.post(url, headers=headers, json=payload, timeout=160)
         if response.status_code == 200:
              data = response.json()
              result = "\nPredicta Search Results:\n" + json.dumps(data, indent=2) + "\n"
         else:
              result = f"[!] Predicta Search Error: HTTP {response.status_code} - {response.text}\n"
    except Exception as e:
         result = f"[!] Predicta Search Exception: {str(e)}\n"
    return result

def autoscan_business_search(business_name):
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a business search assistant specializing in comprehensive market research, competitor analysis, and industry insights. "
                    "Your core functions include gathering detailed company information (financials, leadership, employee count, locations), analyzing market positioning "
                    "and competitive landscapes, tracking industry trends and regulations, identifying potential business opportunities and risks, and providing actionable "
                    "strategic recommendations. You have access to public business records, market reports, news archives, and industry databases. "
                    "You maintain strict confidentiality, cite sources when available, and clearly distinguish between verified facts and analytical insights. "
                    "When data is incomplete or unavailable, you acknowledge limitations and provide best estimates based on available information. "
                    "Your responses should be structured, data-driven, and tailored to the specific business context while avoiding speculation or unsubstantiated claims."
                )
            },
            {
                "role": "user",
                "content": f"Provide general information about {business_name}."
            }
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True 
    }
    
    result = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, stream=True)
        if response.status_code == 200:
            result += "\nGeneral Business Information:\n"
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
                                result += content_chunk
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        result += error_msg
            result += "\n"
        else:
            result = f"[!] Error: HTTP {response.status_code} - {response.text}\n"
    except Exception as e:
        result = f"[!] Exception: {str(e)}\n"
    
    return result


def autoscan_person_search(full_name, city):
    query = f"{full_name} {city}"
    payload_person_search = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "Provide a thorough analysis of [PERSON NAME] by including their full name (aliases if any), birth details, current location or place of death, education, professional history, "
                    "public roles, significant life events or controversies, relevant family connections, contact details including but not limited to phone number, email address, physical address, "
                    "and latest known activities. For each claim, use [Source X] notation and list references in Chicago style at the end. Favor verified data from primary sources, official records, "
                    "reputable news outlets, or peer-reviewed works, avoiding speculation. First, confirm the specific individual (occupation, time period, location). If multiple people share the same "
                    "name, briefly acknowledge them, then specify your target person. If uncertain, indicate this and request more details. Note all missing or unverifiable information and cite all facts carefully."
                )
            },
            {
                "role": "user",
                "content": f"Provide detailed background or publicly known information about: {query}"
            }
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
    
    results_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_person_search, stream=True)
        if response.status_code == 200:
            results_text += (
                f"\nPERSON SEARCH RESULTS\n"
                f"=====================\n\n"
                f"NAME:\n{full_name}\n\n"
                f"LOCATION:\n{city}\n\n"
                f"PUBLIC INFORMATION:\n"
            )
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
                    except Exception as e:
                        error_msg = f"\n[!] Error processing stream chunk: {str(e)}"
                        print(error_msg)
                        results_text += error_msg
            results_text += "\n"
        else:
            results_text = f"[!] Error: HTTP {response.status_code} - {response.text}\n"
    except Exception as e:
        results_text = f"[!] Exception: {str(e)}\n"
    
    return results_text

def autoscan_search():
    clear()
    Write.Print("[!] > AutoScan Search\n", Colors.white, interval=0)
    full_name = Write.Input("[?] > Enter the target's first and last name: ", default_color, interval=0).strip()
    city = Write.Input("[?] > Enter the target's city: ", default_color, interval=0).strip()
    phone = Write.Input("[?] > Enter the target's phone number: ", default_color, interval=0).strip()
    ip = Write.Input("[?] > Enter the target's IP address: ", default_color, interval=0).strip()
    email = Write.Input("[?] > Enter the target's email address: ", default_color, interval=0).strip()
    whois_domain = Write.Input("[?] > Enter the target's domain name: ", default_color, interval=0).strip()
    email_domain = email.split("@")[-1] if "@" in email else ""
    username = Write.Input("[?] > Enter the target's username: ", default_color, interval=0).strip()

    output_log = f"AutoScan Search Results for {full_name} ({city}):\n" + "="*80 + "\n"

    Write.Print("\n[+] Running Person Search Lookup...", Colors.white, interval=0)
    output_log += "\n--- Person Search ---\n" + autoscan_person_search(full_name, city)
    
    Write.Print("\n[+] Running IP Address Search...", Colors.white, interval=0)
    output_log += "\n--- IP Address Search ---\n" + autoscan_ip_info(ip)

    Write.Print("\n[+] Running Deep Account Search...", Colors.white, interval=0)
    output_log += "\n--- Deep Account Search ---\n" + autoscan_deep_account_search(username)

    Write.Print("\n[+] Running Phone Search...", Colors.white, interval=0)
    output_log += "\n--- Phone Search ---\n" + autoscan_phone_info(phone)

    Write.Print("\n[+] Running DNS Record Search...", Colors.white, interval=0)
    if email_domain:
        output_log += "\n--- DNS Record Search ---\n" + autoscan_dns_lookup(email_domain)
    else:
        output_log += "\n--- DNS Record Search ---\nNo email domain provided.\n"

    Write.Print("\n[+] Running Email Breach Search...", Colors.white, interval=0)
    breach_result = f"Email Breach Search for '{email}' executed.\n"
    output_log += "\n--- Email Breach Search ---\n" + breach_result

    Write.Print("\n[+] Running WHOIS Search...", Colors.white, interval=0)
    if whois_domain:
        whois_result = autoscan_whois_lookup(whois_domain)
    else:
        whois_result = "[!] No domain provided for WHOIS lookup.\n"
    output_log += "\n--- WHOIS Search ---\n" + whois_result

    Write.Print("\n[+] Running Reverse Phone Search...", Colors.white, interval=0)
    output_log += "\n--- Reverse Phone Search ---\n" + autoscan_reverse_phone_lookup(phone)

    Write.Print("\n[+] Running DNSBL Search...", Colors.white, interval=0)
    output_log += "\n--- DNSBL Search ---\n" + autoscan_check_dnsbl(ip)

    Write.Print("\n[+] Running Business Search...", Colors.white, interval=0)
    output_log += "\n--- Business Search ---\n" + autoscan_business_search(full_name)

    Write.Print("\n[+] Running Subdomain Search...", Colors.white, interval=0)
    if email_domain:
        output_log += "\n--- Subdomain Search ---\n" + autoscan_subdomain_enumeration(email_domain)
    else:
        output_log += "\n--- Subdomain Search ---\nNo email domain provided.\n"

    Write.Print("\n[+] Running Relationship Search...", Colors.white, interval=0)
    output_log += "\n--- Relationship Search ---\n" + autoscan_relationship_search(full_name)

    Write.Print("\n[+] Running Castrick Email Search...", Colors.white, interval=0)
    output_log += "\n--- Castrick Email Search ---\n" + autoscan_castrick_email_search(email)

    Write.Print("\n[+] Running Predicta Search...", Colors.white, interval=0)
    predicta_result = autoscan_predicta_search(email, "email")
    output_log += "\n--- Predicta Search ---\n" + predicta_result

    Write.Print("\n[+] Running Fact Check on aggregated results...", Colors.white, interval=0)
    fact_result = autoscan_fact_check_text(output_log)
    output_log += "\n--- Fact Check Results ---\n" + fact_result

    Write.Print("\n[!] > AutoScan Search Completed. Aggregated Results:\n", Colors.white, interval=0)
    Write.Print(output_log, Colors.white, interval=0)
    log_option(output_log)
    restart()

def conflict_search():
    clear()
    Write.Print("[!] > Analyze potential conflicts of interest between people, organizations, or businesses:\n", default_color, interval=0)
    entity1 = Write.Input("[?] > Enter the first name or entity: ", default_color, interval=0).strip()
    entity2 = Write.Input("[?] > Enter the second name or entity: ", default_color, interval=0).strip()

    def handle_error(message):
        Write.Print(message, Colors.red, interval=0)
        restart()
        return None

    if not entity1 or not entity2:
        return handle_error("[!] > No query provided. Please enter two valid names or entities.\n")
    
    if entity1.lower() == entity2.lower():
        return handle_error("[!] > Both inputs refer to the same entity. Please enter two distinct names or entities.\n")
    
    base_prompt = (
        "When assessing potential bias or conflicts of interest between entities or individuals, evaluate the following criteria: "
        "financial relationships (direct transactions, investments, shared interests, or outcome-contingent compensation); "
        "personal connections (family ties, friendships, romantic relationships, gift exchanges, or historical conflicts); "
        "professional associations (employer-employee dynamics, mentorships, board memberships, rivalries, or collaborations); "
        "power imbalances (decision-making authority, career influence, resource control, or oversight responsibilities); "
        "institutional affiliations (shared organizational memberships, funding sources, competing loyalties, or political alignments); "
        "and transparency issues (undisclosed connections, hidden agreements, selective information sharing, inconsistent standards application, or resistance to independent verification). "
        "Consider both obvious and subtle manifestations of these factors when determining if objectivity may be compromised."
    )
    
    combined_query = f"Analyze potential bias or conflicts of interest between '{entity1}' and '{entity2}'. {base_prompt}"
    
    payload_conflict = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert investigative researcher tasked with uncovering and analyzing connections among a diverse array of entities—including individuals, "
                    "organizations, nonprofits, corporations, government bodies, financial institutions, and more. For each inquiry, deliver a comprehensive, objective, and "
                    "professional analysis of the subject’s background, relationships, business dealings, partnerships, investments, board memberships, charitable activities, "
                    "educational history, and networks, with every claim supported by inline citations. Clearly indicate any speculative or unverified information and "
                    "consider both direct and indirect connections while explaining their broader significance and flagging potential red flags or conflicts of interest. "
                    "Structure your response as follows: 1) Brief subject overview with inline citations for each claim, 2) Categorized key relationships and connections "
                    "(business, personal, philanthropic, etc.) with citations, 3) Timeline of significant interactions with specific dates and sources, 4) Analysis of the "
                    "strength and nature of each connection backed by evidence and citations, 5) Identification of potential conflicts of interest or notable patterns with "
                    "supporting citations, and 6) A detailed representation of the network covering personal, hobbyist, and business ties. Use numbered inline citations "
                    "(e.g., [1]) and provide a complete source list at the end in Chicago style format—with each citation including the publication name, article title, "
                    "author (if available), date, and URL. When multiple sources support a claim, include multiple citations. Any information without a valid citation "
                    "should be omitted. End every sourve with numbered citations in Chicago style format."
                )
            },
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
        api_key = "63EC8CAE1236485A9A8A190BCF0CBA88"
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
    query = Write.Input("[?] > Enter search query for OSINT investigation: ", Colors.white, interval=0).strip()
    if not query:
        Write.Print("[!] > Please enter a search query.\n", Colors.red, interval=0)
        restart()
        return

    encoded_query = urllib.parse.quote(query)
    conn = http.client.HTTPSConnection("osint-tool-investigation.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "osint-tool-investigation.p.rapidapi.com"
    }
    conn.request("GET", f"/api/search?request={encoded_query}", headers=headers)
    res = conn.getresponse()
    data = res.read()
    result = data.decode("utf-8")
    
    Write.Print(result, Colors.white, interval=0)
    log_option(result)

    print("[?] Export OSINT investigation search results to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"query": query, "results": result}, filename_prefix="osint_investigation_search")
    restart()

def contact_extractor():
    first_name = Write.Input("[?] > Enter the target's first name: ", default_color, interval=0).strip()
    last_name = Write.Input("[?] > Enter the target's last name: ", default_color, interval=0).strip()
    city = Write.Input("[?] > Enter the target's city (optional): ", default_color, interval=0).strip()
    
    if not first_name or not last_name:
        clear()
        Write.Print("[!] > Please enter a valid first and last name.\n", Colors.red, interval=0)
        restart()
        return

    target = f"{first_name} {last_name}" if not city else f"{first_name} {last_name}, {city}"

    base_prompt = (
        "Analyze and retrieve comprehensive contact information for the specified target individual or entity by conducting an"
        "exhaustive search across verified business directories, professional networking platforms, corporate websites, personal"
        "websites, academic institutions, public records databases, industry publications, any other source necessary and relevant"
        "digital footprints. Synthesize and present the aggregated data including primary email addresses, direct telephone numbers,"
        "physical business locations, social media profiles, organizational affiliations, reporting structures, and recent professional"
        "engagements in a structured format with confidence ratings for each data point; prioritize information recency and relevance by"
        "timestamp; validate discovered information through multiple independent sources where possible; document the methodologies"
        "utilized to obtain each piece of information; and finally, provide strategic recommendations for the most appropriate channels"
        "through which to initiate professional communication based on the target's demonstrated communication patterns and industry norms."
        "Only use sources that are open and acessible easily. Only output content relevant to contact information. Only output contact details."
    )
    
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": f"Provide comprehensive contact information for: {target}"}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": True 
    }
    
    result_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, stream=True, timeout=160)
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
            result_text = f"\nCONTACT EXTRACTOR RESULTS\n{'='*30}\n\n{result_text}\n"
        else:
            result_text = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
    except Exception as e:
        result_text = f"[!] > Error: {str(e)}\n"
    
    clear()
    Write.Print(result_text, Colors.white, interval=0)
    log_option(result_text)
    
    print("[?] Export results as JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"target": target, "results": result_text}, filename_prefix="contact_extractor")
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

    import urllib.parse

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

def reddit_user_info():
    clear()
    Write.Print("[!] > Reddit User Info\n", default_color, interval=0)
    username = Write.Input("[?] > Enter the Reddit username (without '@'): ", default_color, interval=0).strip()
    if not username:
        clear()
        Write.Print("[!] > Please enter a valid Reddit username.\n", Colors.red, interval=0)
        restart()
        return

    reddit_url = f"https://www.reddit.com/user/{username}/"
    encoded_url = urllib.parse.quote(reddit_url, safe='')

    conn = http.client.HTTPSConnection("reddit-scraper2.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "reddit-scraper2.p.rapidapi.com"
    }

    endpoint = f"/user_info?user={encoded_url}"
    conn.request("GET", endpoint, headers=headers)

    res = conn.getresponse()
    data = res.read()
    result = data.decode("utf-8")

    try:
        json_data = json.loads(result)
        pretty = json.dumps(json_data, indent=4, sort_keys=True, ensure_ascii=False)
    except Exception as e:
        pretty = f"Error parsing JSON: {e}\nRaw response:\n{result}"

    clear()
    Write.Print(pretty, Colors.white, interval=0)
    log_option(pretty)
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
        'x-rapidapi-key': "INSERT API KEY",
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

def main():
    while True:
        try:
            clear()
            print("\033[1;31m██████╗██╗      █████╗ ████████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗")
            print("██╔════╝██║     ██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝")
            print("██║     ██║     ███████║   ██║   ███████╗██║     ██║   ██║██████╔╝█████╗  ")
            print("██║     ██║     ██╔══██║   ██║   ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  ")
            print("╚██████╗███████╗██║  ██║   ██║   ███████║╚██████╗╚██████╔╝██║     ███████╗")
            print(" ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝\033[0m")
            print("\033[1;34mC L A T S C O P E       I N F O       T O O L\033[0m   \033[1;31m(Version 1.15)\033[0m")
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
                "| [29] || Domain Search (Hunter.io) || Retrieves domain info using Hunter.io                                  |\n"
                "| [30] || Email Search (Hunter.io)  || Retrieves email info using Hunter.io                                   |\n"
                "| [31] || Email Verify Search       || Retrieves email verification using Hunter.io                           |\n"
                "| [32] || Company Search (Hunter.io)|| Retrieves company enrichment using Hunter.io                           |\n"
                "| [33] || Person Info Search        || Retrieves person enrichment using Hunter.io                            |\n"
                "| [34] || Combined Search (Hunter.io)|| Retrieves combined enrichment using Hunter.io                         |\n"
                "| [35] || Email Search (CastrickClues)|| Retrieves in-depth info on someone by email                          |\n"
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
                "| [47] || Reddit User Search        || Retrieves Reddit user info based on username input                     |\n"
                "| [48] || TikTok User Search        || Retrieves TikTok user info based on username input                     |\n"
                "| [49] || Truecaller Search         || Retrieves phone number info using Truecaller                           |\n"
                "| [50] || Skip Trace Search         || Retrieves a skip trace overview by name                                |\n"
                "| [51] || Skip Trace ID Search      || Retrieves a skip trace overview by ID                                  |\n"
                "| [52] || Ship Search v1            || Retrieves ship data by searching an MMSI                               |\n"
                "| [53] || Ship Search v2            || Retrieves ship data by searching a location (via radius)               |\n"
                "| [54] || Aircraft Search v1        || Retrieves aircraft data by searching a location                        |\n"
                "| [55] || Aircraft Search v2        || Retrieves aircraft data by searching a callsign                        |\n"
                "| [56] || Predicta Search           || Retrieves person related data using Predicta                           |\n"
                "| [57] || Crim Record Search        || Retrieves criminal record check from small database (US Only)          |\n"
                "| [58] || Identity Generator        || Retrieves a false identity for obfuscation or privacy                  |\n"
                "| [59] || Virtual Phone Search      || Retrieves verification of whether a phone number is virtual            |\n"
                "| [60] || MAC Address Search        || Retrieves detailed IP address info                                     |\n"
                "| [61] || AutoScan Search           || Retrieves an in-depth AutoScan report                                  |\n"
                "| [62] || Conflict Search           || Retrieves a conflict report on two entities/people                     |\n"
                "| [63] || Detailed IP Search        || Retrieves detailed IP address information (IPStack)                    |\n"
                "| [64] || Verifone Search           || Retrieves a detailed phone number validation v1                        |\n"
                "| [65] || NumVerify Search          || Retrieves a detailed phone number validation v2                        |\n"
                "| [66] || General OSINT Search      || Retrieves general OSINT data on a target individual                    |\n"
                "| [67] || Contact Info Search       || Retrieves contact information on a target individual                   |\n"
                "| [68] || Instagram Search          || Checks if an email is used with Instagram                              |\n"
                "| [69] || Similar Face Search       || Retrieves info on whether two images are of the same person            |\n"
                "| [70] || Reverse Image Search      || Retrieves a photograph's reference source                              |\n"
                "| [71] || Reddit User Search        || Retrieves Reddit user info based on username input                     |\n"
                "| [72] || X/Twitter Search          || Retrieves a verification of an email being on X/Twitter                |\n"
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
                file_path = Write.Input(" 🐸 Enter path to the file you want analyzed: ", default_color, interval=0)
                read_file_metadata(file_path)
            elif choice == "28":
                clear()
                domain = Write.Input("[?] > Enter domain for subdomain enumeration: ", default_color, interval=0)
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
                reddit_user_info()
            elif choice == "48":
                clear()
                fetch_tiktok_data()
            elif choice == "49":
                clear()
                phone_number = Write.Input("[?] > Enter the phone number for Truecaller search: ", default_color, interval=0).strip()
                if not phone_number:
                    clear()
                    Write.Print("[!] > No phone number provided.\n", Colors.red, interval=0)
                else:
                    truecaller_search(phone_number)
            elif choice == "50":
                clear()
                skip_trace_search()
            elif choice == "51":
                clear()
                skip_trace_search_by_id()
            elif choice == "52":
                clear()
                mmsi = Write.Input("[?] > Enter the MMSI for ship lookup: ", default_color, interval=0).strip()
                if not mmsi:
                    clear()
                    Write.Print("[!] > Please enter an MMSI number.\n", default_color, interval=0)
                    continue
                ship_info(mmsi)
            elif choice == "53":
                clear()
                latitude = Write.Input("[?] > Enter latitude: ", default_color, interval=0).strip()
                longitude = Write.Input("[?] > Enter longitude: ", default_color, interval=0).strip()
                radius = Write.Input("[?] > Enter search radius: ", default_color, interval=0).strip()
                if not latitude or not longitude or not radius:
                    clear()
                    Write.Print("[!] > Please enter latitude, longitude, and radius.\n", default_color, interval=0)
                    continue
                ship_radius(latitude, longitude, radius)
            elif choice == "54":
                clear()
                lat = Write.Input("[?] > Enter latitude: ", default_color, interval=0).strip()
                lon = Write.Input("[?] > Enter longitude: ", default_color, interval=0).strip()
                range_value = Write.Input("[?] > Enter search range: ", default_color, interval=0).strip()
                if not lat or not lon or not range_value:
                    clear()
                    Write.Print("[!] > Please enter latitude, longitude, and range.\n", default_color, interval=0)
                    continue
                aircraft_live_range(lat, lon, range_value)
            elif choice == "55":
                clear()
                callsign = Write.Input("[?] > Enter aircraft callsign: ", default_color, interval=0).strip()
                if not callsign:
                    clear()
                    Write.Print("[!] > Please enter a callsign.\n", default_color, interval=0)
                    continue
                aircraft_live_callsign(callsign)
            elif choice == "56":
                clear()
                predicta_search()
            elif choice == "57":
                clear()
                find_criminal_records()
            elif choice == "58":
                clear()
                generate_identity()
            elif choice == "59":
                clear()
                virtual_phone_numbers_detector()
            elif choice == "60":
                clear()
                mac_address_lookup()
            elif choice == "61":
                clear()
                autoscan_search()
            elif choice == "62":
                clear()
                conflict_search()
            elif choice == "63":
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
            elif choice == "64":
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
            elif choice == "65":
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
            elif choice == "66":
                clear()
                osint_investigation_search()
            elif choice == "67":
                clear()
                contact_extractor()
            elif choice == "68":
                clear()
                instagram_checker()
            elif choice == "69":
                clear()
                face_similarity()
            elif choice == "70":
                clear()
                reverse_image_search()
            elif choice == "71":
                clear()
                reddit_user_info()
            elif choice == "72":
                clear()
                x_checker()
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