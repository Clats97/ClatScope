import tkinter as +34 676 20 01 04
from tkinter import ttk, scrolledtext, simpledialog, messagebox, filedialog
import requests
from phonenumbers import geocoder, carrier
import phonenumbers 676200104
import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
from dns import reversename
from email_validator import validate_email, EmailNotValidError
from urllib.parse import quote
import secrets
import json
from bs4 import BeautifulSoup
import re
from email.parser import Parser
import whois
from tqdm import tqdm
from datetime import datetime
import openai
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
import multiprocessing

default_color = 'white'
HIBP_API_KEY = "INSERT API KEY HERE"
HUNTER_API_KEY = "INSERT API KEY HERE"
CASTRICK_API_KEY = "INSERT API KEY HERE"
VIRUSTOTAL_API_KEY = "INSERT API KEY HERE"
OPENAI_API_KEY = "INSERT API KEY HERE"
PERPLEXITY_API_KEY = "INSERT API KEY HERE"
RAPIDAPI_KEY = "INSERT API KEY HERE"

_global_session = requests.Session()
requests.get = _global_session.get

MAX_WORKERS = min(32, (multiprocessing.cpu_count() or 1) * 5)


class ClatScopeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ClatScope Info Tool v1.09.1")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)

        # Create a single ThreadPoolExecutor to handle all tasks
        self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        self.task_count = 0  # Track tasks in progress

        # Create main frames
        header_frame = ttk.Frame(root)
        header_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        button_frame = ttk.Frame(root)
        button_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        output_frame = ttk.Frame(root)
        output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Display ASCII Art and Author Information (centered)
        ascii_art = (
            "██████╗    ██╗          █████╗     ████████╗    ███████╗     ██████╗     ██████╗     ██████╗     ███████╗\n"
            "██╔════╝    ██║         ██╔══██╗    ╚══██╔══╝    ██╔════╝    ██╔════╝    ██╔═══██╗    ██╔══██╗    ██╔════╝\n"
            "██║         ██║         ███████║       ██║       ███████╗    ██║         ██║   ██║    ██████╔╝    █████╗  \n"
            "██║         ██║         ██╔══██║       ██║       ╚════██║    ██║         ██║   ██║    ██╔═══╝     ██╔══╝  \n"
            "╚██████╗    ███████╗    ██║  ██║       ██║       ███████║    ╚██████╗    ╚██████╔╝    ██║         ███████╗\n"
            " ╚═════╝    ╚══════╝    ╚═╝  ╚═╝       ╚═╝       ╚══════╝     ╚═════╝     ╚═════╝     ╚═╝         ╚══════╝\n"
            "C L A T S C O P E       I N F O       T O O L   (Version 1.10.1)\n"
        )
        author = "By Joshua Clatney - Ethical Pentesting Enthusiast\n[OSINT]\nOpen Sources. Clear Conclusions\n"

        header_label = ttk.Label(header_frame, text=ascii_art + author, justify=tk.CENTER, anchor="center", font=("Courier", 10))
        header_label.pack()

        # Progress label
        self.progress_label = ttk.Label(header_frame, text="", font=("Arial", 12))
        self.progress_label.pack()

        # Create a canvas and scrollbar for the buttons
        canvas = tk.Canvas(button_frame, width=300)
        scrollbar = ttk.Scrollbar(button_frame, orient="vertical", command=canvas.yview)
        self.buttons_inner_frame = ttk.Frame(canvas)
        self.buttons_inner_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=self.buttons_inner_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Output area with scrollbar
        self.output_textbox = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, state='disabled', font=("Courier", 10))
        self.output_textbox.pack(fill=tk.BOTH, expand=True)

        # Create buttons for each function
        self.create_buttons()

    # ------------------ Utility Methods ------------------
    def show_in_progress(self):
        self.task_count += 1
        self.progress_label.config(text="Your request is in progress....")

    def hide_in_progress(self, future):
        def _hide():
            self.task_count -= 1
            if self.task_count <= 0:
                self.task_count = 0
                self.progress_label.config(text="")
        self.root.after(0, _hide)

    def clear_output(self):
        self.output_textbox.config(state=tk.NORMAL)
        self.output_textbox.delete('1.0', tk.END)
        self.output_textbox.config(state=tk.DISABLED)

    def gui_print(self, text, color='white'):
        self.output_textbox.config(state=tk.NORMAL)
        self.output_textbox.insert(tk.END, text + "\n")
        self.output_textbox.tag_add(color, "end-2c linestart", "end-1c lineend")
        self.output_textbox.tag_config(color, foreground=color)
        self.output_textbox.see(tk.END)
        self.output_textbox.config(state=tk.DISABLED)

    def gui_input(self, prompt):
        return simpledialog.askstring("Input", prompt, parent=self.root)

    def log_option(self, output_text):
        if messagebox.askyesno("Save Log", "Would you like to save this output to a log file?"):
            stamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
            with open("clatscope_log.txt", "a", encoding="utf-8") as log_file:
                log_file.write(f"{stamp}{output_text}\n\n")
            self.gui_print("[!] > Output has been saved to clatscope_log.txt")

    def timeConvert(self, atime):
        newtime = datetime.fromtimestamp(atime)
        return newtime.date()

    def sizeFormat(self, size):
        newsize = format(size/1024, ".2f")
        return newsize + " KB"

    def get_permission_string(self, file_mode):
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

    def gps_extract(self, exif_dict):
        gps_metadata = exif_dict['GPSInfo']
        lat_ref_num = 1 if gps_metadata['GPSLatitudeRef'] == 'N' else -1
        lat_list = [float(num) for num in gps_metadata['GPSLatitude']]
        lat_coordinate = (lat_list[0] + lat_list[1]/60 + lat_list[2]/3600) * lat_ref_num
        long_ref_num = 1 if gps_metadata['GPSLongitudeRef'] == 'E' else -1
        long_list = [float(num) for num in gps_metadata['GPSLongitude']]
        long_coordinate = (long_list[0] + long_list[1]/60 + long_list[2]/3600) * long_ref_num
        return (lat_coordinate, long_coordinate)

    def check_password_strength(self, password):
        txt_file_path = os.path.join(os.path.dirname(__file__), "passwords.txt")
        if os.path.isfile(txt_file_path):
            try:
                with open(txt_file_path, "r", encoding="utf-8") as f:
                    common_words = f.read().splitlines()
                for word in common_words:
                    if word and word in password:
                        return "Weak password (may contain common phrase or word)"
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
            return "Weak password"
        elif 3 <= score <= 4:
            return "Moderate password"
        else:
            return "Strong password"

    # ------------------ Button Creation ------------------
    def create_buttons(self):
        functions = [
            ("1", "IP Address Search", self.ip_info_gui),
            ("2", "Deep Account Search", self.deep_account_search_gui),
            ("3", "Phone Search", self.phone_info_gui),
            ("4", "DNS Record Search", self.dns_lookup_gui),
            ("5", "Email MX Search", self.email_lookup_gui),
            ("6", "Person Name Search", self.person_search_gui),
            ("7", "Reverse DNS Search", self.reverse_dns_gui),
            ("8", "Email Header Search", self.analyze_email_header_gui),
            ("9", "Email Breach Search", self.haveibeenpwned_check_gui),
            ("10", "WHOIS Search", self.whois_lookup_gui),
            ("11", "Password Analyzer", self.password_strength_tool_gui),
            ("12", "Username Search", self.username_check_gui),
            ("13", "Reverse Phone Search", self.reverse_phone_lookup_gui),
            ("14", "SSL Search", self.check_ssl_cert_gui),
            ("15", "Web Crawler Search", self.check_robots_and_sitemap_gui),
            ("16", "DNSBL Search", self.check_dnsbl_gui),
            ("17", "Web Metadata Search", self.fetch_webpage_metadata_gui),
            ("18", "Travel Risk Search", self.travel_assessment_gui),
            ("19", "Botometer Search", self.botometer_search_gui),
            ("20", "Business Search", self.business_search_gui),
            ("21", "HR Email Search", self.hudson_rock_email_infection_check_gui),
            ("22", "HR Username Search", self.hudson_rock_username_infection_check_gui),
            ("23", "HR Domain Search", self.hudson_rock_domain_infection_check_gui),
            ("24", "HR IP Search", self.hudson_rock_ip_infection_check_gui),
            ("25", "Fact Check Search", self.fact_check_text_gui),
            ("26", "Relationship Search", self.relationship_search_gui),
            ("27", "File Metadata Search", self.read_file_metadata_gui),
            ("28", "Subdomain Search", self.subdomain_enumeration_gui),
            ("29", "Domain Search (Hunter.io)", self.hunter_domain_search_gui),
            ("30", "Email Search (Hunter.io)", self.hunter_email_finder_gui),
            ("31", "Email Verify Search (Hunter.io)", self.hunter_email_verifier_gui),
            ("32", "Company Search (Hunter.io)", self.hunter_company_enrichment_gui),
            ("33", "Person Info Search (Hunter.io)", self.hunter_person_enrichment_gui),
            ("34", "Combined Search (Hunter.io)", self.hunter_combined_enrichment_gui),
            ("35", "Email Search (CastrickClues)", self.castrick_email_search_gui),
            ("36", "Domain Report (VirusTotal)", self.virustotal_domain_report_gui),
            ("37", "Malice Search", self.malice_search_gui),
            ("0", "Exit", self.exit_gui)
        ]
        for num, name, command in functions:
            btn = ttk.Button(self.buttons_inner_frame, text=f"[{num}] {name}", command=command)
            btn.pack(fill=tk.X, padx=5, pady=2)

    # ------------------ GUI Handler Methods ------------------
    def ip_info_gui(self):
        ip = self.gui_input("Enter IP Address:")
        if ip:
            self.clear_output()
            self.gui_print(f"Fetching information for IP: {ip}")
            self.show_in_progress()
            future = self.executor.submit(self.ip_info, ip)
            future.add_done_callback(self.hide_in_progress)

    def deep_account_search_gui(self):
        nickname = self.gui_input("Enter Username:")
        if nickname:
            self.clear_output()
            self.gui_print(f"Performing Deep Account Search for username: {nickname}")
            self.show_in_progress()
            future = self.executor.submit(self.deep_account_search, nickname)
            future.add_done_callback(self.hide_in_progress)

    def phone_info_gui(self):
        phone_number = self.gui_input("Enter Phone Number:")
        if phone_number:
            self.clear_output()
            self.gui_print(f"Fetching phone information for: {phone_number}")
            self.show_in_progress()
            future = self.executor.submit(self.phone_info, phone_number)
            future.add_done_callback(self.hide_in_progress)

    def dns_lookup_gui(self):
        domain = self.gui_input("Enter Domain/URL:")
        if domain:
            self.clear_output()
            self.gui_print(f"Performing DNS lookup for: {domain}")
            self.show_in_progress()
            future = self.executor.submit(self.dns_lookup, domain)
            future.add_done_callback(self.hide_in_progress)

    def email_lookup_gui(self):
        email = self.gui_input("Enter Email:")
        if email:
            self.clear_output()
            self.gui_print(f"Performing Email MX lookup for: {email}")
            self.show_in_progress()
            future = self.executor.submit(self.email_lookup, email)
            future.add_done_callback(self.hide_in_progress)

    def person_search_gui(self):
        first_name = self.gui_input("Enter First Name:")
        last_name = self.gui_input("Enter Last Name:")
        city = self.gui_input("Enter City/Location:")
        if first_name and last_name:
            self.clear_output()
            self.gui_print(f"Performing Person Search for: {first_name} {last_name}, {city}")
            self.show_in_progress()
            future = self.executor.submit(self.person_search, first_name, last_name, city)
            future.add_done_callback(self.hide_in_progress)
        else:
            messagebox.showerror("Error", "First Name and Last Name are required.")

    def reverse_dns_gui(self):
        ip = self.gui_input("Enter IP Address:")
        if ip:
            self.clear_output()
            self.gui_print(f"Performing Reverse DNS lookup for: {ip}")
            self.show_in_progress()
            future = self.executor.submit(self.reverse_dns, ip)
            future.add_done_callback(self.hide_in_progress)

    def analyze_email_header_gui(self):
        raw_headers = self.gui_input("Paste Raw Email Headers:")
        if raw_headers:
            self.clear_output()
            self.gui_print("Analyzing Email Headers...")
            self.show_in_progress()
            future = self.executor.submit(self.analyze_email_header, raw_headers)
            future.add_done_callback(self.hide_in_progress)

    def haveibeenpwned_check_gui(self):
        email = self.gui_input("Enter Email Address:")
        if email:
            self.clear_output()
            self.gui_print(f"Checking if email has been pwned: {email}")
            self.show_in_progress()
            future = self.executor.submit(self.haveibeenpwned_check, email)
            future.add_done_callback(self.hide_in_progress)

    def whois_lookup_gui(self):
        domain = self.gui_input("Enter Domain/URL:")
        if domain:
            self.clear_output()
            self.gui_print(f"Performing WHOIS lookup for: {domain}")
            self.show_in_progress()
            future = self.executor.submit(self.whois_lookup, domain)
            future.add_done_callback(self.hide_in_progress)

    def password_strength_tool_gui(self):
        password = simpledialog.askstring("Password Analyzer", "Enter Password:", show='*', parent=self.root)
        if password:
            self.clear_output()
            self.gui_print("Analyzing password strength...")
            self.show_in_progress()
            future = self.executor.submit(self.password_strength_tool, password)
            future.add_done_callback(self.hide_in_progress)

    def username_check_gui(self):
        username = self.gui_input("Enter Username:")
        if username:
            self.clear_output()
            self.gui_print(f"Checking username: {username}")
            self.show_in_progress()
            future = self.executor.submit(self.username_check, username)
            future.add_done_callback(self.hide_in_progress)

    def reverse_phone_lookup_gui(self):
        phone_number = self.gui_input("Enter phone number or name to perfoem a reverse lookup:")
        if phone_number:
            self.clear_output()
            self.gui_print(f"Performing Reverse Phone lookup for: {phone_number}")
            self.show_in_progress()
            future = self.executor.submit(self.reverse_phone_lookup, phone_number)
            future.add_done_callback(self.hide_in_progress)

    def check_ssl_cert_gui(self):
        domain = self.gui_input("Enter Domain/URL:")
        if domain:
            self.clear_output()
            self.gui_print(f"Checking SSL certificate for: {domain}")
            self.show_in_progress()
            future = self.executor.submit(self.check_ssl_cert, domain)
            future.add_done_callback(self.hide_in_progress)

    def check_robots_and_sitemap_gui(self):
        domain = self.gui_input("Enter Domain:")
        if domain:
            self.clear_output()
            self.gui_print(f"Checking robots.txt and sitemap.xml for: {domain}")
            self.show_in_progress()
            future = self.executor.submit(self.check_robots_and_sitemap, domain)
            future.add_done_callback(self.hide_in_progress)

    def check_dnsbl_gui(self):
        ip_address = self.gui_input("Enter IP Address:")
        if ip_address:
            self.clear_output()
            self.gui_print(f"Performing DNSBL check for IP: {ip_address}")
            self.show_in_progress()
            future = self.executor.submit(self.check_dnsbl, ip_address)
            future.add_done_callback(self.hide_in_progress)

    def fetch_webpage_metadata_gui(self):
        url = self.gui_input("Enter URL:")
        if url:
            self.clear_output()
            self.gui_print(f"Fetching webpage metadata for: {url}")
            self.show_in_progress()
            future = self.executor.submit(self.fetch_webpage_metadata, url)
            future.add_done_callback(self.hide_in_progress)

    def travel_assessment_gui(self):
        location = self.gui_input("Enter Location:")
        if location:
            self.clear_output()
            self.gui_print(f"Performing Travel Risk Assessment for: {location}")
            self.show_in_progress()
            future = self.executor.submit(self.travel_assessment, location)
            future.add_done_callback(self.hide_in_progress)

    def botometer_search_gui(self):
        username = self.gui_input("Enter X/Twitter Username:")
        if username:
            self.clear_output()
            self.gui_print(f"Checking Botometer score for: {username}")
            self.show_in_progress()
            future = self.executor.submit(self.botometer_search, username)
            future.add_done_callback(self.hide_in_progress)

    def business_search_gui(self):
        business_name = self.gui_input("Enter Business or Person's Name:")
        if business_name:
            self.clear_output()
            self.gui_print(f"Performing Business Search for: {business_name}")
            self.show_in_progress()
            future = self.executor.submit(self.business_search, business_name)
            future.add_done_callback(self.hide_in_progress)

    def hudson_rock_email_infection_check_gui(self):
        email = self.gui_input("Enter Email to Check Infection Status:")
        if email:
            self.clear_output()
            self.gui_print(f"Checking infection status for email: {email}")
            self.show_in_progress()
            future = self.executor.submit(self.hudson_rock_email_infection_check, email)
            future.add_done_callback(self.hide_in_progress)

    def hudson_rock_username_infection_check_gui(self):
        username = self.gui_input("Enter Username to Check Infection Status:")
        if username:
            self.clear_output()
            self.gui_print(f"Checking infection status for username: {username}")
            self.show_in_progress()
            future = self.executor.submit(self.hudson_rock_username_infection_check, username)
            future.add_done_callback(self.hide_in_progress)

    def hudson_rock_domain_infection_check_gui(self):
        domain = self.gui_input("Enter Domain/URL to Check Infection Status:")
        if domain:
            self.clear_output()
            self.gui_print(f"Checking infection status for domain: {domain}")
            self.show_in_progress()
            future = self.executor.submit(self.hudson_rock_domain_infection_check, domain)
            future.add_done_callback(self.hide_in_progress)

    def hudson_rock_ip_infection_check_gui(self):
        ip_address = self.gui_input("Enter IP Address to Check Infection Status:")
        if ip_address:
            self.clear_output()
            self.gui_print(f"Checking infection status for IP: {ip_address}")
            self.show_in_progress()
            future = self.executor.submit(self.hudson_rock_ip_infection_check, ip_address)
            future.add_done_callback(self.hide_in_progress)

    def fact_check_text_gui(self):
        text_to_check = self.gui_input("Enter Text to Fact-Check:")
        if text_to_check:
            self.clear_output()
            self.gui_print("Performing Fact Check...")
            self.show_in_progress()
            future = self.executor.submit(self.fact_check_text, text_to_check)
            future.add_done_callback(self.hide_in_progress)

    def relationship_search_gui(self):
        query = self.gui_input("Enter Query to Analyze Relationships:")
        if query:
            self.clear_output()
            self.gui_print(f"Analyzing relationships for: {query}")
            self.show_in_progress()
            future = self.executor.submit(self.relationship_search, query)
            future.add_done_callback(self.hide_in_progress)
        else:
            messagebox.showerror("Error", "A query is required.")

    def read_file_metadata_gui(self):
        file_path = filedialog.askopenfilename(title="Select File for Metadata Analysis")
        if file_path:
            self.clear_output()
            self.gui_print(f"🐢 Checking File Data\n {file_path}")
            self.show_in_progress()
            future = self.executor.submit(self.read_file_metadata, file_path)
            future.add_done_callback(self.hide_in_progress)

    def subdomain_enumeration_gui(self):
        domain = self.gui_input("Enter Domain for Subdomain Enumeration:")
        if domain:
            self.clear_output()
            self.gui_print(f"Performing Subdomain Enumeration for: {domain}")
            self.show_in_progress()
            future = self.executor.submit(self.subdomain_enumeration, domain)
            future.add_done_callback(self.hide_in_progress)

    def hunter_domain_search_gui(self):
        domain = self.gui_input("Enter Domain to Search via Hunter.io:")
        if domain:
            self.clear_output()
            self.gui_print(f"Performing Hunter.io Domain Search for: {domain}")
            self.show_in_progress()
            future = self.executor.submit(self.hunter_domain_search, domain)
            future.add_done_callback(self.hide_in_progress)

    def hunter_email_finder_gui(self):
        domain = self.gui_input("Enter Domain (e.g., reddit.com):")
        first_name = self.gui_input("Enter First Name:")
        last_name = self.gui_input("Enter Last Name:")
        if domain and first_name and last_name:
            self.clear_output()
            self.gui_print(f"Performing Hunter.io Email Finder for: {first_name} {last_name} @ {domain}")
            self.show_in_progress()
            future = self.executor.submit(self.hunter_email_finder, domain, first_name, last_name)
            future.add_done_callback(self.hide_in_progress)
        else:
            messagebox.showerror("Error", "Domain, First Name, and Last Name are required.")

    def hunter_email_verifier_gui(self):
        email = self.gui_input("Enter Email to Verify:")
        if email:
            self.clear_output()
            self.gui_print(f"Performing Hunter.io Email Verification for: {email}")
            self.show_in_progress()
            future = self.executor.submit(self.hunter_email_verifier, email)
            future.add_done_callback(self.hide_in_progress)

    def hunter_company_enrichment_gui(self):
        domain = self.gui_input("Enter Domain for Company Enrichment:")
        if domain:
            self.clear_output()
            self.gui_print(f"Performing Hunter.io Company Enrichment for: {domain}")
            self.show_in_progress()
            future = self.executor.submit(self.hunter_company_enrichment, domain)
            future.add_done_callback(self.hide_in_progress)

    def hunter_person_enrichment_gui(self):
        email = self.gui_input("Enter Email for Person Enrichment:")
        if email:
            self.clear_output()
            self.gui_print(f"Performing Hunter.io Person Enrichment for: {email}")
            self.show_in_progress()
            future = self.executor.submit(self.hunter_person_enrichment, email)
            future.add_done_callback(self.hide_in_progress)

    def hunter_combined_enrichment_gui(self):
        email = self.gui_input("Enter Email for Combined Enrichment:")
        if email:
            self.clear_output()
            self.gui_print(f"Performing Hunter.io Combined Enrichment for: {email}")
            self.show_in_progress()
            future = self.executor.submit(self.hunter_combined_enrichment, email)
            future.add_done_callback(self.hide_in_progress)

    def castrick_email_search_gui(self):
        email = self.gui_input("Enter Email to Check via CastrickClues:")
        if email:
            self.clear_output()
            self.gui_print(f"Performing CastrickClues Email Search for: {email}")
            self.show_in_progress()
            future = self.executor.submit(self.castrick_email_search, email)
            future.add_done_callback(self.hide_in_progress)

    def virustotal_domain_report_gui(self):
        domain = self.gui_input("Enter domain for VirusTotal report:")
        if domain:
            self.clear_output()
            self.show_in_progress()
            future = self.executor.submit(self.virustotal_domain_report, domain)
            future.add_done_callback(self.hide_in_progress)

    def malice_search_gui(self):
        input_text = self.gui_input("Enter text to analyze for malicious content:")
        if input_text:
            self.clear_output()
            self.gui_print("Performing Malice Search...")
            self.show_in_progress()
            future = self.executor.submit(self.malice_search, input_text)
            future.add_done_callback(self.hide_in_progress)

    def exit_gui(self):
        self.executor.shutdown(wait=False)
        self.root.quit()

    # ------------------ Worker Methods (Functionality) ------------------
    def subdomain_enumeration(self, domain):
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except json.JSONDecodeError:
                    msg = "[!] > Error: crt.sh returned non-JSON or empty data."
                    self.gui_print(msg)
                    messagebox.showerror("Subdomain Enumeration", msg)
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
                    self.gui_print(out_text)
                    if messagebox.askyesno("Save Log", "Would you like to save this output to a log file?"):
                        stamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
                        with open("clatscope_log.txt", "a", encoding="utf-8") as f:
                            f.write(stamp + out_text + "\n")
                        self.gui_print("[!] > Subdomains saved to clatscope_log.txt")
                else:
                    msg = "[!] > No subdomains found."
                    self.gui_print(msg)
                    messagebox.showinfo("Subdomain Enumeration", msg)
            else:
                err = f"[!] > HTTP {resp.status_code} from crt.sh"
                self.gui_print(err)
                messagebox.showerror("Subdomain Enumeration", err)
        except Exception as exc:
            err_msg = f"[!] > Subdomain enumeration error: {exc}"
            self.gui_print(err_msg)
            messagebox.showerror("Subdomain Enumeration", err_msg)

    def validate_domain_input(self, domain):
        if not domain or len(domain) > 253 or ".." in domain:
            return False
        pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, domain))

    def get_ip_details(self, ip):
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=30)
            response.raise_for_status()
            return response.json()
        except:
            return None

    def person_search(self, first_name, last_name, city):
        query = f"{first_name} {last_name} {city}"
        payload_person_search = {
            "model": "sonar-reasoning-pro",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "When searching for information about [PERSON NAME], please provide a comprehensive analysis that includes:"
                        "their full name including any variations or aliases; date and place of birth (if known); current location or"
                        "place of death if deceased; educational background including institutions and years of attendance; professional"
                        "history with dates and notable achievements; any significant public roles or positions held; major life events"
                        "or controversies; family connections and relationships relevant to their public life; and their current status"
                        "or most recent known activities. For any claims made, include specific citations using [Source X] notation"
                        "within the text, where X corresponds to the numbered source in the reference list. Each piece of information"
                        "should be attributed to at least one credible source, with preference given to primary sources, official records,"
                        "reputable news organizations, and peer-reviewed academic works where applicable. Avoid speculation beyond verifiable"
                        "data. When researching [PERSON NAME], first verify the specific individual by their distinguishing characteristics"
                        "(occupation, time period, location, or notable achievements). If the person has appeared in a news article or public interview, discuss the details of it."
                        "If multiple people share similar names, acknowledge their existence at the beginning of your response like this: Note: There are other notable individuals named"
                        "[Similar Name], including [Brief one-line identifier for each]. This analysis focuses on [Target Person] who is known for [Key Identifier]."
                        "Then proceed with the detailed analysis of only the target individual, including their background, achievements, and current status."
                        "If you cannot confidently distinguish between similarly named individuals based on the available context, state this uncertainty clearly"
                        "and list the potential matches with their key identifiers, requesting additional details to ensure accurate identification. All information"
                        "should be properly cited using numbered references, and only include verified information about the specific target individual. At the end of the analysis,"
                        "provide a numbered list of all sources cited, including full bibliographic information (author, title, publication, date, URL if applicable) in Chicago style format."
                        "If any critical information is missing orunverifiable, explicitly note these gaps in the analysis. Include information about their current job, employment status, and other relevant professional information."
                    )
                },
                {
                    "role": "user",
                    "content": f"Provide detailed background or publicly known information about: {query}"
                }
            ],
            "max_tokens": 8000,
            "temperature": 1.1
        }
        PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
        perplexity_headers = {
            "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
            "Content-Type": "application/json",
        }
        results_text = ""
        try:
            response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_person_search)
            if response.status_code == 200:
                data = response.json()
                info_content = data["choices"][0]["message"]["content"]
                results_text = (
                    f"\nPERSON SEARCH RESULTS\n"
                    f"=====================\n\n"
                    f"NAME:\n{first_name} {last_name}\n\n"
                    f"LOCATION:\n{city}\n\n"
                    f"PUBLIC INFORMATION:\n{info_content}\n"
                )
            else:
                results_text = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
        except Exception as e:
            results_text = f"[!] > Error: {e}\n"
        self.gui_print(results_text)
        self.log_option(results_text)

    def fetch_page_text(self, url):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36)"
        }
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "lxml")
            for tag_name in ["header", "footer", "nav", "aside", "script", "style", "noscript", "form"]:
                for t in soup.find_all(tag_name):
                    t.decompose()
            text = soup.get_text(separator=' ')
            text = ' '.join(text.split())
            return text if text else "No meaningful content found."
        except Exception:
            return "Could not retrieve or parse the webpage content."

    def ip_info(self, ip):
        try:
            data = self.get_ip_details(ip)
            if data:
                output = json.dumps(data, indent=2)
                self.gui_print(f"IP Information:\n{output}")
                messagebox.showinfo("IP Address Search", "IP information retrieved successfully.")
            else:
                self.gui_print("[!] > Could not retrieve IP information.")
                messagebox.showerror("IP Address Search", "Could not retrieve IP information.")
        except Exception as e:
            self.gui_print(f"[!] > Error: {e}")
            messagebox.showerror("IP Address Search", f"An error occurred: {e}")

    def fetch_social_urls(self, urls, title):
        def check_url(url):
            try:
                response = requests.get(url, timeout=30)
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

        result_str = f"""
╭─{' '*78}─╮
|{' '*27}{title}{' '*27}|
|{'='*80}|
"""
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            results = list(executor.map(check_url, urls))
        for result in results:
            result_str += f"| {result:<78} |\n"
        result_str += f"╰─{' '*78}─╯"
        return result_str

    def deep_account_search(self, nickname):
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
            "https://steamcommunity.com/id/{target}",
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
            "https://archive.org/details/@{target}",
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
        search_results = self.fetch_social_urls(urls, "Deep Account Search")
        self.gui_print(search_results)
        self.log_option(search_results)

    def phone_info(self, phone_number):
        try:
            parsed_number = phonenumbers.parse(phone_number)
            country = geocoder.country_name_for_number(parsed_number, "en")
            region = geocoder.description_for_number(parsed_number, "en")
            operator = carrier.name_for_number(parsed_number, "en")
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
            self.gui_print(phonetext)
            self.log_option(phonetext)
        except phonenumbers.phonenumberutil.NumberParseException:
            msg = "\n[!] > Error: invalid phone number format (+1-000-000-0000)"
            self.gui_print(msg)
            messagebox.showerror("Phone Search", msg)

    def reverse_phone_lookup(self, phone_number):
        PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
        payload_reverse_phone_lookup = {
            "model": "sonar-reasoning-pro",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a specialized reverse phone lookup assistant that provides bidirectional search capabilities between phone numbers "
                        "and individual/business names across public directories and databases. You search for phone numbers from a name or business name, "
                        "or search for a name or business name based on a phone number. You help users find associated contact information. You clarify search "
                        "parameters when needed and provide relevant contextual details about found associations. You must cite all your sources at the end of the prompt."
                    )
                },
                {
                    "role": "user",
                    "content": f"Perform a reverse phone lookup for the following number: {phone_number}"
                }
            ],
            "max_tokens": 8000,
            "temperature": 1.1
        }
        perplexity_headers = {
            "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
            "Content-Type": "application/json",
        }
        results_text = ""
        try:
            response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_reverse_phone_lookup, timeout=30)
            if response.status_code == 200:
                data = response.json()
                results_text = "\nReverse Phone Lookup Results:\n" + data["choices"][0]["message"]["content"] + "\n"
            else:
                results_text = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
        except Exception as e:
            results_text = f"[!] > Exception in reverse phone lookup: {e}\n"
        self.gui_print(results_text)
        self.log_option(results_text)

    def dns_lookup(self, domain):
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
        self.gui_print(result_output)
        self.log_option(result_output)

    def email_lookup(self, email_address):
        try:
            v = validate_email(email_address)
            email_domain = v.domain
        except EmailNotValidError as e:
            msg = f"[!] > Invalid email address format: {e}"
            self.gui_print(msg)
            messagebox.showerror("Email MX Search", msg)
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
        self.gui_print(email_text)
        self.log_option(email_text)

    def reverse_dns(self, ip):
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
        self.gui_print(rdns_text)
        self.log_option(rdns_text)

    def analyze_email_header(self, raw_headers):
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
        self.gui_print(header_text)
        if found_ips:
            ip_details_header = f"""
╭─{' '*78}─╮
|{' '*30}IP Geolocation Details{' '*30}|
|{'='*80}|
"""
            ip_details_summary = ""
            for ip in found_ips:
                data = self.get_ip_details(ip)
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
            self.gui_print(ip_details_full)
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
        self.gui_print(alignment_text)
        full_output = header_text + "\n" + alignment_text
        self.log_option(full_output)

    def haveibeenpwned_check(self, email):
        headers = {
            "hibp-api-key": HIBP_API_KEY,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36)"
        }
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code == 200:
                breaches = resp.json()
                box_width = 80
                header_line = f"Have I Been Pwned? - Breach Report for {email}"
                top_border = f"╭─{'─' * (box_width - 4)}─╮"
                header_center = f"| {header_line.center(box_width - 4)} |"
                middle_border = f"|{'=' * box_width}|"
                breach_summary = f"| [!] > Bad news! Your email was found in {len(breaches)} breach(es)".ljust(box_width - 1) + "|"
                breach_separator = f"|{'-' * box_width}|"
                results_text = f"{top_border}\n{header_center}\n{middle_border}\n{breach_summary}\n{breach_separator}\n"
                for index, breach in enumerate(breaches, start=1):
                    breach_name = breach.get('Name', 'Unknown')[:60]
                    domain_val = breach.get('Domain', 'Unknown')[:60]
                    breach_date = breach.get('BreachDate', 'Unknown')[:20]
                    added_date = breach.get('AddedDate', 'Unknown')[:20]
                    pwn_count = str(breach.get('PwnCount', 'Unknown'))[:15]
                    data_classes = ", ".join(breach.get('DataClasses', [])).replace(',', ', ').strip()[:60]
                    results_text += (
                        f"| Breach #{index}: {breach_name:<60} |\n"
                        f"|    Domain: {domain_val:<60} |\n"
                        f"|    Breach Date: {breach_date:<20}    |\n"
                        f"|    Added Date:  {added_date:<20}    |\n"
                        f"|    PwnCount:    {pwn_count:<15}    |\n"
                        f"|    Data Types:  {data_classes:<60} |\n"
                        f"|{'=' * box_width}|\n"
                    )
                bottom_border = f"╰─{'─' * (box_width - 4)}─╯"
                results_text += f"{bottom_border}"
                self.gui_print(results_text)
                self.log_option(results_text)
                messagebox.showinfo("Have I Been Pwned?", "Email breaches retrieved successfully.")
            elif resp.status_code == 404:
                box_width = 80
                header_line = f"Have I Been Pwned? - Breach Report for {email}"
                top_border = f"╭─{'─' * (box_width - 4)}─╮"
                header_center = f"| {header_line.center(box_width - 4)} |"
                middle_border = f"|{'=' * box_width}|"
                good_news = f"| [!] > Good news! No breaches found for: {email:<48} |"
                bottom_border = f"╰─{'─' * (box_width - 4)}─╯"
                msg = f"{top_border}\n{header_center}\n{middle_border}\n{good_news}\n{bottom_border}"
                self.gui_print(msg)
                self.log_option(msg)
                messagebox.showinfo("Have I Been Pwned?", "No breaches found for the email.")
            else:
                error_msg = f"[!] > An error occurred: HTTP {resp.status_code}\nResponse: {resp.text}"
                self.gui_print(error_msg)
                self.log_option(error_msg)
                messagebox.showerror("Have I Been Pwned?", f"An error occurred: HTTP {resp.status_code}")
        except requests.exceptions.Timeout:
            msg = "[!] > Request timed out when contacting Have I Been Pwned."
            self.gui_print(msg)
            messagebox.showerror("Have I Been Pwned?", msg)
        except Exception as e:
            msg = f"[!] > An error occurred: {e}"
            self.gui_print(msg)
            messagebox.showerror("Have I Been Pwned?", f"An error occurred: {e}")

    def whois_lookup(self, domain):
        try:
            w = whois.whois(domain)
            whois_text = f"""
╭─{' '*78}─╮
|{' '*30}WHOIS Information{' '*30}|
|{'='*80}|
"""
            for key, value in w.items():
                whois_text += f"| {str(key):<20}: || {str(value)[:54]:<54}|\n"
            whois_text += f"╰─{' '*78}─╯"
            self.gui_print(whois_text)
            self.log_option(whois_text)
            messagebox.showinfo("WHOIS Search", "WHOIS information retrieved successfully.")
        except Exception as e:
            msg = f"[!] > Error: {e}"
            self.gui_print(msg)
            messagebox.showerror("WHOIS Search", f"An error occurred: {e}")

    def password_strength_tool(self, password):
        strength = self.check_password_strength(password)
        output_text = f"Password Strength: {strength}"
        self.gui_print(output_text)
        self.log_option(output_text)
        messagebox.showinfo("Password Analyzer", "Password strength analyzed successfully.")

    def username_check(self, username):
        # (This function was not fully implemented in the original menu.)
        self.gui_print(f"Username check for {username} not implemented.")
        messagebox.showinfo("Username Search", "Username check not implemented.")

    def check_ssl_cert(self, domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=30) as sock:
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
            self.gui_print(info_text)
            self.log_option(info_text)
            messagebox.showinfo("SSL Search", "SSL certificate information retrieved successfully.")
        except ssl.SSLError as e:
            msg = f"[!] > SSL Error: {e}"
            self.gui_print(msg)
            messagebox.showerror("SSL Search", msg)
        except socket.timeout:
            msg = "[!] > Connection timed out."
            self.gui_print(msg)
            messagebox.showerror("SSL Search", msg)
        except Exception as e:
            msg = f"[!] > An error occurred retrieving SSL cert info: {e}"
            self.gui_print(msg)
            messagebox.showerror("SSL Search", msg)

    def check_robots_and_sitemap(self, domain):
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
                resp = requests.get(resource_url, timeout=30)
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
                result_text += f"| Error: {e}\n"
                result_text += f"|{'='*80}|\n"
        result_text += f"╰─{' '*78}─╯"
        self.gui_print(result_text)
        self.log_option(result_text)
        messagebox.showinfo("Web Crawler Search", "Site discovery completed successfully.")

    def check_dnsbl(self, ip_address):
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
                results.append((dnsbl, f"Error: {e}"))
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
        self.gui_print(report)
        self.log_option(report)

    def fetch_webpage_metadata(self, url):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36))"
        }
        try:
            resp = requests.get(url, headers=headers, timeout=30)
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
            self.gui_print(result_text)
            self.log_option(result_text)
            messagebox.showinfo("Web Metadata Search", "Webpage metadata retrieved successfully.")
        except Exception as e:
            msg = f"[!] > Error fetching metadata: {e}"
            self.gui_print(msg)
            messagebox.showerror("Web Metadata Search", msg)

    def travel_assessment(self, location):
        prompt = f"""
Provide a comprehensive, highly detailed travel risk analysis for the following location: {location}.

                    "You are a travel risk analysis assistant specializing in providing comprehensive, detailed, and practical risk assessments for travel destinations. "
                    "Your responses should cover political stability, crime rates, natural disasters, health risks, local laws, infrastructure, and other relevant factors. "
                    "Ensure that your analysis is thorough, well-structured, and includes practical advice, best practices, and necessary disclaimers with clear citations if applicable."

Include disclaimers about rapidly changing conditions, and note that official government websites
and reputable sources (e.g., WHO, CDC, local government portals) should be consulted for the most
up-to-date information.
"""
        payload_travel = {
            "model": "sonar-reasoning-pro",
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert travel risk assessment assistant that provides detailed, comprehensive analyses."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": 8000,
            "temperature": 1.1
        }
        PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
        perplexity_headers = {
            "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
            "Content-Type": "application/json",
        }
        try:
            response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_travel)
            if response.status_code == 200:
                data = response.json()
                analysis = data["choices"][0]["message"]["content"]
                self.gui_print(analysis)
                self.log_option(analysis)
                messagebox.showinfo("Travel Risk Assessment", "Travel risk analysis completed successfully.")
            else:
                msg = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
                self.gui_print(msg)
                messagebox.showerror("Travel Risk Assessment", msg)
        except Exception as e:
            msg = f"[!] > An error occurred: {e}"
            self.gui_print(msg)
            messagebox.showerror("Travel Risk Assessment", msg)

    def botometer_search(self, username):
        try:
            url = "https://botometer-pro.p.rapidapi.com/botometer-x/get_botscores_in_batch"
            payload = {
                "user_ids": [],
                "usernames": [username]
            }
            headers = {
                "x-rapidapi-key": RAPIDAPI_KEY,
                "x-rapidapi-host": "botometer-pro.p.rapidapi.com",
                "Content-Type": "application/json"
            }
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            result = response.json()
            output_text = json.dumps(result, indent=2)
            self.gui_print(output_text)
            self.log_option(output_text)
            messagebox.showinfo("Botometer Search", "Botometer score retrieved successfully.")
        except Exception as e:
            msg = f"[!] > Error: {e}"
            self.gui_print(msg)
            messagebox.showerror("Botometer Search", f"An error occurred: {e}")

    def business_search(self, business_name):
        PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
        payload_business_info = {
            "model": "sonar-reasoning-pro",
            "messages": [
                {
                    "role": "system",
                    "content":(
                        "You are a business search assistant specializing in comprehensive market research, competitor analysis, and industry insights." 
                        "Your core functions include gathering detailed company information (financials, leadership, employee count, locations), analyzing" 
                        "market positioning and competitive landscapes, tracking industry trends and regulations, identifying potential business opportunities" 
                        "and risks, and providing actionable strategic recommendations. You have access to public business records, market reports, news archives." 
                        "and industry databases. You maintain strict confidentiality, cite sources when available, and clearly distinguish between verified facts" 
                        "and analytical insights. When data is incomplete or unavailable, you acknowledge limitations and provide best estimates based on available" 
                        "information. Your responses should be structured, data-driven, and tailored to the specific business context while avoiding speculation or" 
                        "unsubstantiated claims." 
                    )
                },
                {
                    "role": "user",
                    "content": f"Provide me with general information about {business_name}."
                }
            ],
            "max_tokens": 8000,
            "temperature": 1.1,
        }
        try:
            headers = {
                "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
                "Content-Type": "application/json",
            }
            response = requests.post(PERPLEXITY_API_URL, headers=headers, json=payload_business_info)
            if response.status_code == 200:
                data = response.json()
                out_text = "\nGeneral Business Information:\n" + data["choices"][0]["message"]["content"] + "\n"
                self.gui_print(out_text)
                messagebox.showinfo("Business Search", "Business information retrieved successfully.")
            else:
                err_msg = f"Error: {response.status_code}, {response.text}\n"
                self.gui_print(err_msg)
                messagebox.showerror("Business Search", f"Failed to retrieve business information.\n{err_msg}")
        except Exception as e:
            out_text = f"[!] > Exception in retrieving business info: {e}\n"
            self.gui_print(out_text)
            messagebox.showerror("Business Search", f"An error occurred: {e}")
        self.log_option(out_text)

    def hudson_rock_email_infection_check(self, email):
        try:
            url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
            params = {"email": email}
            resp = requests.get(url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            output_lines = [f"[+] Hudson Rock email infection check results for {email}:\n"]
            if isinstance(data, dict):
                for k, v in data.items():
                    output_lines.append(f"{k}: {v}")
            else:
                output_lines.append("No structured data available.")
            output_text = "\n".join(output_lines)
            self.gui_print("\n" + output_text)
            self.log_option(output_text)
            messagebox.showinfo("HR Email Search", "Email infection status retrieved successfully.")
        except requests.exceptions.Timeout:
            msg = "[!] > Request timed out when contacting Hudson Rock."
            self.gui_print(msg)
            messagebox.showerror("HR Email Search", msg)
        except Exception as e:
            msg = f"[!] > Error: {e}"
            self.gui_print(msg)
            messagebox.showerror("HR Email Search", f"An error occurred: {e}")
        self.log_option(output_text)

    def hudson_rock_username_infection_check(self, username):
        try:
            url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username"
            params = {"username": username}
            resp = requests.get(url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            output_lines = [f"[+] Hudson Rock username infection check results for {username}:\n"]
            if isinstance(data, dict):
                for k, v in data.items():
                    output_lines.append(f"{k}: {v}")
            else:
                output_lines.append("No structured data available.")
            output_text = "\n".join(output_lines)
            self.gui_print("\n" + output_text)
            self.log_option(output_text)
            messagebox.showinfo("HR Username Search", "Username infection status retrieved successfully.")
        except requests.exceptions.Timeout:
            msg = "[!] > Request timed out when contacting Hudson Rock."
            self.gui_print(msg)
            messagebox.showerror("HR Username Search", msg)
        except Exception as e:
            msg = f"[!] > Error: {e}"
            self.gui_print(msg)
            messagebox.showerror("HR Username Search", f"An error occurred: {e}")
        self.log_option(output_text)

    def hudson_rock_domain_infection_check(self, domain):
        try:
            url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
            params = {"domain": domain}
            resp = requests.get(url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            output_lines = [f"[+] Hudson Rock domain infection check results for {domain}:\n"]
            if isinstance(data, dict):
                for k, v in data.items():
                    output_lines.append(f"{k}: {v}")
            else:
                output_lines.append("No structured data available.")
            output_text = "\n".join(output_lines)
            self.gui_print("\n" + output_text)
            self.log_option(output_text)
            messagebox.showinfo("HR Domain Search", "Domain infection status retrieved successfully.")
        except requests.exceptions.Timeout:
            msg = "[!] > Request timed out when contacting Hudson Rock."
            self.gui_print(msg)
            messagebox.showerror("HR Domain Search", msg)
        except Exception as e:
            msg = f"[!] > Error: {e}"
            self.gui_print(msg)
            messagebox.showerror("HR Domain Search", f"An error occurred: {e}")
        self.log_option(output_text)

    def hudson_rock_ip_infection_check(self, ip_address):
        try:
            url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-ip"
            params = {"ip": ip_address}
            resp = requests.get(url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            output_lines = [f"[+] Hudson Rock IP infection check results for {ip_address}:\n"]
            if isinstance(data, dict):
                for k, v in data.items():
                    output_lines.append(f"{k}: {v}")
            else:
                output_lines.append("No structured data available.")
            output_text = "\n".join(output_lines)
            self.gui_print("\n" + output_text)
            self.log_option(output_text)
            messagebox.showinfo("HR IP Search", "IP infection status retrieved successfully.")
        except requests.exceptions.Timeout:
            msg = "[!] > Request timed out when contacting Hudson Rock."
            self.gui_print(msg)
            messagebox.showerror("HR IP Search", msg)
        except Exception as e:
            msg = f"[!] > Error: {e}"
            self.gui_print(msg)
            messagebox.showerror("HR IP Search", f"An error occurred: {e}")
        self.log_option(output_text)

    def fact_check_text(self, text_to_check):
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
                        "cite all sources at the end of the output and make sure they are numbered accurately."
                    )
                },
                {"role": "user", "content": f"Fact-check the following text: {text_to_check}"}
            ],
            "max_tokens": 8000,
            "temperature": 1.1
        }
        PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
        perplexity_headers = {
            "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
            "Content-Type": "application/json",
        }
        output_text = ""
        try:
            response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_fact_check)
            if response.status_code == 200:
                data = response.json()
                output_text = "\nFact Checking Results:\n" + data["choices"][0]["message"]["content"] + "\n"
                self.gui_print(output_text)
                messagebox.showinfo("Fact Check", "Fact checking completed successfully.")
            else:
                err_msg = f"Error: {response.status_code}, {response.text}\n"
                output_text = err_msg
                self.gui_print(err_msg)
                messagebox.showerror("Fact Check", f"Failed to fact-check.\n{err_msg}")
        except Exception as e:
            output_text = f"[!] > Exception in fact-checking: {e}\n"
            self.gui_print(output_text)
            messagebox.showerror("Fact Check", f"An error occurred: {e}")
        self.log_option(output_text)

    def relationship_search(self, query):
        payload_relationships = {
            "model": "sonar-reasoning-pro",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an expert investigative researcher tasked with uncovering and analyzing connections between entities,"
                        "people, organizations, not for profits, foundations, sole proprietorships, trusts, lobbyists, partnerships, LLCs,"
                        "charities, social advocacy groups, trade and professional associations, recreational clubs, fraternal societies,"
                        "employee beneficiary associations, political action committes, govermnment agencies and departments, political parties,"
                        "soverign wealth funds, diplomatic missions / embassies, holding companies, joint ventures, cooperatives, professional corporations,"
                        "s-corporations, universities and colleges, research institutions, think tanks, academic consortiums, investment funds, hedge funds,"
                        "private equity firms, venture capital firms, mutual fund holdings, stock holdings, banking institutions, credit unions, churches,"
                        "religious orders, faith-based organizations, media companies, news organizations, broadcasting networks, hospital systems, medical practices,"
                        "healthcare consortiums, international trade organizations, intergovernmental organizations and community service groups,"
                        "For each query, thoroughly analyze the subject's background, relationships, business dealings,"
                        "partnerships, investments, board memberships, charitable activities, educational history,"
                        "professional networks and anything else. If information is speculative or unverified, clearly indicate this. Consider both direct"
                        "and indirect connections, and explain the significance of each relationship within the broader context."
                        "Flag any potential red flags or areas requiring further investigation. Your analysis should be objective,"
                        "thorough, and professional in tone, avoiding speculation while highlighting substantiated connections and"
                        "their implications. You must cite sources. Structure your response in the following format: 1) Brief overview of"
                        "the subject [EACH CLAIM MUST INCLUDE AN INLINE CITATION], 2) Key relationships and connections,"
                        "categorized by type (business, personal, philanthropic, etc.) [EVERY CONNECTION MUST BE CITED],"
                        "3) Timeline of significant interactions or partnerships [CITE SPECIFIC DATES AND SOURCES], 4)"
                        "Analysis of the strength and nature of each connection [INCLUDE EVIDENCE AND CITATIONS FOR EACH ASSESSMENT],"
                        "5) Identification of any potential conflicts of interest or notable patterns [SUPPORT WITH SPECIFIC CITATIONS],"
                        "6) Detailed textual representation of the network, personal, hobbyist and business connections. When analyzing business entities, include"
                        "parent companies, subsidiaries, joint ventures, major shareholders, and key personnel. For individuals, consider"
                        "family ties, business associates, political connections, and social networks. REQUIRED CITATION FORMAT:"
                        "Use numbered inline citations [1] and provide a complete source list at the end of your response."
                        "Each citation must include: publication name, article title, author (if available), date, and URL if applicable."
                        "Any information without a citation will be considered invalid and must be removed. If a claim combines multiple"
                        "sources, use multiple citations [1][2]. For unverified or speculative information, explicitly state Unverified: and"
                        "explain why the information lacks definitive sourcing and why it remains valuable. Your analysis should maintain strict objectivity, relying solely"
                        "on verifiable sources while highlighting substantiated connections and their implications. Circumstantial facts are allowed but should not be relied upon and only included in the report if neccessary,"
                        "END EVERY RESPONSE WITH: Sources: followed by numbered citations in Chicago style format."
                    )
                },
                {"role": "user", "content": query}
            ],
            "max_tokens": 8000,
            "temperature": 1.1
        }
        PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
        perplexity_headers = {
            "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
            "Content-Type": "application/json",
        }
        output_text = ""
        try:
            response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_relationships)
            if response.status_code == 200:
                data = response.json()
                output_text = "\nEntity Relationship Analysis Results:\n" + data["choices"][0]["message"]["content"] + "\n"
                self.gui_print(output_text)
                messagebox.showinfo("Relationship Search", "Relationship analysis completed successfully.")
            else:
                err_msg = f"Error: {response.status_code}, {response.text}\n"
                output_text = err_msg
                self.gui_print(err_msg)
                messagebox.showerror("Relationship Search", f"Failed to analyze relationships.\n{err_msg}")
        except Exception as e:
            output_text = f"[!] > Exception in relationship analysis: {e}\n"
            self.gui_print(output_text)
            messagebox.showerror("Relationship Search", f"An error occurred: {e}")
        self.log_option(output_text)

    def read_file_metadata(self, file_path):
        self.gui_print(f"🐢 Checking File Data\n {file_path}")
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File {file_path} does not exist.")
            Dfile = os.stat(file_path)
            file_size = self.sizeFormat(Dfile.st_size)
            file_name = os.path.basename(file_path)
            max_length = 60
            file_creation_time = self.timeConvert(Dfile.st_birthtime)
            file_modification_time = self.timeConvert(Dfile.st_mtime)
            file_last_Access_Date = self.timeConvert(Dfile.st_atime)
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)
            metaData_extra = []
            permissions = self.get_permission_string(Dfile.st_mode)
            if(file_type.startswith("image")):
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
                    for label, value in info_dict.items():
                        metaData_extra.append(f"|  {str(label):<10}: ||  {str(value)[:max_length]:<60}|")
                    if img.format == 'TIFF':
                        for tag_id, value in img.tag_v2.items():
                            tag_name = TAGS.get(tag_id, tag_id)
                            metaData_extra.append(f"|  {str(tag_name):<10}: ||  {str(value)[:max_length]:<60}|")
                    elif(file_path.endswith('.png')):
                        for key, value in img.info.items():
                            metaData_extra.append(f"|  {str(key):<10}: ||  {str(value)[:max_length]:<60}|")
                    else:
                        imdata = img._getexif()
                        if imdata:
                            for tag_id in imdata:
                                tag = TAGS.get(tag_id, tag_id)
                                data = imdata.get(tag_id)
                                if(tag == "GPSInfo"):
                                    gps = self.gps_extract(imdata)
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
            elif(file_type == "application/pdf"):
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
            elif(file_path.endswith(('.doc', '.docx'))):
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
            elif(file_path.endswith(('.xlsx', '.xlsm'))):
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
            elif(file_path.endswith(('.pptx', '.pptm'))):
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
            elif(file_type.startswith("audio")):
                try:
                    metaData_extra.append(f"|{' '*32}Audio MetaData{' '*32}|")
                    metaData_extra.append(f"|{'-'*78}|")
                    tinytag_obj = TinyTag.get(file_path)
                    if(tinytag_obj):
                        metaData_extra.append(f"|  Title:    || {str(tinytag_obj.title)[:max_length]:<60}      |")
                        metaData_extra.append(f"|  Artist:   || {str(tinytag_obj.artist)[:max_length]:<60}     |")
                        metaData_extra.append(f"|  Genre:    || {str(tinytag_obj.genre)[:max_length]:<60}      |")
                        metaData_extra.append(f"|  Album:    || {str(tinytag_obj.album)[:max_length]:<60}      |")
                        metaData_extra.append(f"|  Year:     || {str(tinytag_obj.year)[:max_length]:<60}       |")
                        metaData_extra.append(f"|  Composer: || {str(tinytag_obj.composer)[:max_length]:<60}   |")
                        metaData_extra.append(f"|  A-Artist: || {str(tinytag_obj.albumartist)[:max_length]:<60}|")
                        metaData_extra.append(f"|  Track:    || {str(tinytag_obj.track_total)[:max_length]:<60}|")
                        metaData_extra.append(f"|  Duration: || {f'{tinytag_obj.duration:.2f} seconds':<60}    |")
                        metaData_extra.append(f"|  Bitrate:  || {str(tinytag_obj.bitrate) + ' kbps':<60}       |")
                        metaData_extra.append(f"|  Samplerate:|| {str(tinytag_obj.samplerate) + ' Hz':<60}     |")
                        metaData_extra.append(f"|  Channels: || {str(tinytag_obj.channels):<60}                |")
                    else:
                        metaData_extra.append("Unsupported audio file for metadata extraction.")
                except Exception as e:
                    metaData_extra.append(f"Error processing file: {e}")
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
|  Last Access: || {str(file_last_Access_Date):<60}  |
"""
            metadata_summary += "\n".join(metaData_extra)
            metadata_summary += "\n" + "="*78 + "\n"
            self.gui_print(metadata_summary)
            self.log_option(metadata_summary)
        except Exception as e:
            err_msg = f" ☠ Error reading file metadata: {e}"
            self.gui_print(err_msg)
            messagebox.showerror("File Metadata Search", err_msg)

    def hunter_domain_search(self, domain):
        try:
            url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={HUNTER_API_KEY}"
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            output_text = f"\n[+] Hunter.io Domain Search results for {domain}:\n"
            if isinstance(data, dict):
                for k, v in data.items():
                    output_text += f"{k}: {v}\n"
            else:
                output_text += "No structured domain data available."
            self.gui_print("\n" + output_text)
            self.log_option(output_text)
            messagebox.showinfo("Hunter.io Domain Search", "Domain search completed successfully.")
        except Exception as e:
            output_text = f"[!] > Error: {e}"
            self.gui_print(output_text)
            messagebox.showerror("Hunter.io Domain Search", f"An error occurred: {e}")
            self.log_option(output_text)

    def hunter_email_finder(self, domain, first_name, last_name):
        try:
            url = f"https://api.hunter.io/v2/email-finder?domain={domain}&first_name={first_name}&last_name={last_name}&api_key={HUNTER_API_KEY}"
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            output_text = f"\n[+] Hunter.io Email Finder results for {first_name} {last_name} @ {domain}:\n"
            if isinstance(data, dict):
                for k, v in data.items():
                    output_text += f"{k}: {v}\n"
            else:
                output_text += "No structured email finder data available."
            self.gui_print("\n" + output_text)
            self.log_option(output_text)
            messagebox.showinfo("Hunter.io Email Finder", "Email search completed successfully.")
        except Exception as e:
            output_text = f"[!] > Error: {e}"
            self.gui_print(output_text)
            messagebox.showerror("Hunter.io Email Finder", f"An error occurred: {e}")
            self.log_option(output_text)

    def hunter_email_verifier(self, email):
        try:
            url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={HUNTER_API_KEY}"
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            output_text = f"\n[+] Hunter.io Email Verification results for {email}:\n"
            if isinstance(data, dict):
                for k, v in data.items():
                    output_text += f"{k}: {v}\n"
            else:
                output_text += "No structured verifier data available."
            self.gui_print("\n" + output_text)
            self.log_option(output_text)
            messagebox.showinfo("Hunter.io Email Verification", "Email verification completed successfully.")
        except Exception as e:
            output_text = f"[!] > Error: {e}"
            self.gui_print(output_text)
            messagebox.showerror("Hunter.io Email Verification", f"An error occurred: {e}")
            self.log_option(output_text)

    def hunter_company_enrichment(self, domain):
        try:
            url = f"https://api.hunter.io/v2/companies/find?domain={domain}&api_key={HUNTER_API_KEY}"
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            output_text = f"\n[+] Hunter.io Company Enrichment results for {domain}:\n"
            if isinstance(data, dict):
                for k, v in data.items():
                    output_text += f"{k}: {v}\n"
            else:
                output_text += "No structured company data available."
            self.gui_print("\n" + output_text)
            self.log_option(output_text)
            messagebox.showinfo("Hunter.io Company Enrichment", "Company enrichment completed successfully.")
        except Exception as e:
            output_text = f"[!] > Error: {e}"
            self.gui_print(output_text)
            messagebox.showerror("Hunter.io Company Enrichment", f"An error occurred: {e}")
            self.log_option(output_text)

    def hunter_person_enrichment(self, email):
        try:
            url = f"https://api.hunter.io/v2/people/find?email={email}&api_key={HUNTER_API_KEY}"
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            output_text = f"\n[+] Hunter.io Person Enrichment results for {email}:\n"
            if isinstance(data, dict):
                for k, v in data.items():
                    output_text += f"{k}: {v}\n"
            else:
                output_text += "No structured person data available."
            self.gui_print("\n" + output_text)
            self.log_option(output_text)
            messagebox.showinfo("Hunter.io Person Enrichment", "Person enrichment completed successfully.")
        except Exception as e:
            output_text = f"[!] > Error: {e}"
            self.gui_print(output_text)
            messagebox.showerror("Hunter.io Person Enrichment", f"An error occurred: {e}")
            self.log_option(output_text)

    def hunter_combined_enrichment(self, email):
        try:
            url = f"https://api.hunter.io/v2/combined/find?email={email}&api_key={HUNTER_API_KEY}"
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            output_text = f"\n[+] Hunter.io Combined Enrichment results for {email}:\n"
            if isinstance(data, dict):
                for k, v in data.items():
                    output_text += f"{k}: {v}\n"
            else:
                output_text += "No structured combined data available."
            self.gui_print("\n" + output_text)
            self.log_option(output_text)
            messagebox.showinfo("Hunter.io Combined Enrichment", "Combined enrichment completed successfully.")
        except Exception as e:
            output_text = f"[!] > Error: {e}"
            self.gui_print(output_text)
            messagebox.showerror("Hunter.io Combined Enrichment", f"An error occurred: {e}")
            self.log_option(output_text)

    def castrick_email_search(self, email):
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
                        lines.append(f"| {row_title:<76}|| {str(value):<60}|")
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    row_title = f"{prefix}[{idx}]:"
                    if isinstance(item, (dict, list)):
                        lines.append(f"| {row_title:<76}|")
                        lines.extend(tableify(item, indent + 2))
                    else:
                        lines.append(f"| {row_title:<76}|| {str(item):<60}|")
            else:
                lines.append(f"| {prefix.strip():<76}|| {str(obj):<60}|")
            return lines

        try:
            type_ = "email"
            query = email
            api_key = CASTRICK_API_KEY
            headers = {"api-key": api_key}
            url = f"https://api.castrickclues.com/api/v1/search?query={query}&type={type_}"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            lines = []
            lines.append(f"╭─{' '*78}─╮")
            lines.append(f"|{' '*30}Castrick Email Search{' '*30}|")
            lines.append(f"|{'='*80}|")
            lines.append(f"| Email Queried: {email:<63}|")
            lines.append(f"|{'-'*80}|")
            table_lines = tableify(data)
            if not table_lines:
                lines.append("| No structured data returned from Castrick.|")
            else:
                lines.extend(table_lines)
            lines.append(f"╰─{' '*78}─╯")
            output_text = "\n".join(lines)
            self.gui_print("\n" + output_text)
            self.log_option(output_text)
            messagebox.showinfo("CastrickClues Email Search", "Email search completed successfully.")
        except Exception as e:
            output_text = f"[!] > Error: {e}"
            self.gui_print(output_text)
            messagebox.showerror("CastrickClues Email Search", f"An error occurred: {e}")
            self.log_option(output_text)

    def virustotal_domain_report(self, domain):
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                formatted_data = json.dumps(data, indent=2)
                self.gui_print(f"[+] VirusTotal Domain Report for {domain}:\n{formatted_data}")
            else:
                self.gui_print(f"[!] > Error: HTTP {response.status_code} - {response.text}")
        except Exception as e:
            self.gui_print(f"[!] > Exception: {e}")

    def generate_html_report(self, username, found_sites):
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
        </tr>"""
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

    # ------------------ NEW MALICE SEARCH FUNCTION ------------------
    def malice_search(self, text):
        """
        Uses the Perplexity API with the sonar-reasoning-pro model to evaluate the input text for malicious content.
        The system prompt instructs the model to check for indicators of phishing, scams, and other malicious patterns.
        """
        payload_malice = {
            "model": "sonar-reasoning-pro",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a specialized text analysis system designed to evaluate and identify potentially malicious content in user-provided text. "
                        "Analyze the input for common indicators of phishing attempts (urgent language, requests for sensitive information, impersonation of legitimate entities), "
                        "scam patterns (promises of unrealistic rewards, pressure tactics, unusual payment requests), and other malicious features (social engineering tactics, manipulation attempts, "
                        "suspicious links or contact information). Compare the text against known patterns of fraudulent communications, examining factors such as urgency, emotional manipulation, "
                        "grammatical irregularities, and suspicious requests. For each analysis, provide a risk assessment categorized as: Low Risk (minimal to no suspicious elements present), "
                        "Medium Risk (some concerning elements but lacking definitive malicious intent), or High Risk (multiple red flags indicating likely malicious intent). "
                        "Include specific reasons for the risk classification and highlight the concerning elements identified. Consider context, tone, linguistic patterns, and requested actions when "
                        "determining the risk level. Provide your assessment in a structured format that clearly outlines the risk level, identified suspicious elements, and reasoning behind the classification. "
                        "Flag any immediate security concerns that require urgent attention."
                    )
                },
                {
                    "role": "user",
                    "content": f"Analyze the following text for malicious content:\n{text}"
                }
            ],
            "max_tokens": 8000,
            "temperature": 1.1
        }
        PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
        headers = {
            "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
            "Content-Type": "application/json",
        }
        result_text = ""
        try:
            response = requests.post(PERPLEXITY_API_URL, headers=headers, json=payload_malice, timeout=30)
            if response.status_code == 200:
                data = response.json()
                result_text = "\nMalice Search Results:\n" + data["choices"][0]["message"]["content"] + "\n"
            else:
                result_text = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
        except Exception as e:
            result_text = f"[!] > Exception in Malice Search: {e}\n"
        self.gui_print(result_text)
        self.log_option(result_text)

# ------------------ Main ------------------
def main():
    root = tk.Tk()
    app = ClatScopeGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()