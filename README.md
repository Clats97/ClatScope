# ClatScope Info Tool

ClatScope Info Tool – A versatile OSINT utility for retrieving geolocation, DNS, WHOIS, phone, email, usernames, person related data, password strength, data breach information and more. Perfect for investigators, pentesters, or anyone looking for a quick reconnaissance script. **This script requires API keys for some functions (Google Custom Search, OpenAI, Perplexity, Have I Been Pwned, Botometer, Hunter, Castrick, RapidAPI). If you do not want to set up your own API keys, below there is a subscription service. Otherwise, you are free to use this script as you see fit.**

![icons8-downloads-100](https://github.com/user-attachments/assets/c66d02a6-1186-4d21-8568-272968e5b3ed)

![clatscopeinfo](https://github.com/user-attachments/assets/e0060201-2e10-41c2-b892-ba73726e1209)

Command Line Interface Version:

![clatscopecli](https://github.com/user-attachments/assets/85a17e63-8a81-4405-ad47-846367c1c923)

Graphical User Interface Version:

![clatscopegui](https://github.com/user-attachments/assets/a67b2954-8cfa-4744-8683-648a01672b49)

**DONT WANT TO SET UP YOUR API KEYS TO GET FULL FUNCTIONALITY OF CLATSCOPE INFO TOOL? STARTING JANUARY 12, 2024 A SUBSCRIPTION SERVICE IS AVAILABLE. YOU WILL BE PROVIDED WITH A CUSTOM SCRIPT WITH API KEYS THAT LOGS IP ADDRESS, USER AGENT, USAGE, AND OTHER DETAILS TO ENSURE THERE IS NO UNAUTHORIZED ACCESS OR MISUSE. SHARING IS PROHIBITED AND WILL RESULT IN AN IMMEDIATE REVOCATION OF THE KEY. TURN OFF YOUR VPN WHEN USING IT TO PREVENT AN AUTOMATIC BAN FOR IMPOSSIBLE TRAVEL / SHARING. ALL API KEYS ARE PROTECTED BY WAAP & CLOUEDFLARE API SECURITY. YOUR SUBSCRIPTION IS VALID FOR 30 DAYS. IF YOU RENEW, YOU WILL BE ISSUED A NEW KEY AT THE START OF YOUR RENEWAL. KEYS ARE ROTATED MONTHLY AND ARE SINGLE USE AND MONITORED. EMAIL SKYLINE92X@PM.ME FOR DETAILS.** 

**SUBSCRIPTION LINKS:**

**TIER 1: https://buymeacoffee.com/clats97/e/357348.**

**TIER 2: https://buymeacoffee.com/clats97/e/361894**

**NO REFUNDS**

ClatScope is an OSINT tool that performs various lookups and analyzes provided data.

Throughout the script, a textual UI is presented, prompting the user for inputs (e.g., IP address, phone number). Results are printed in styled ASCII frames using the pystyle library for aesthetics.

**Version:** 1.14 (CLI)1.10.2 (GUI) (2025-02-06)
**Author:** Joshua M Clatney aka Clats97 (Ethical Pentesting Enthusiast)

## Description
ClatScope Info Tool is an all-in-one OSINT (Open-Source Intelligence) utility script that queries public APIs, DNS records, and other online resources to gather and display information about IPs, domains, emails, phone numbers, and more. You will need to enter the required API keys to take advantage of all the features ClatScope Info Tool v1.02 has to offer.

## Features
1. **IP Information** – Extract IP geolocation, ISP, and Google Maps link.  
2. **Deep Account Search & Username Search** – Check over 250 websites to see if a given username exists.  
3. **Phone Number Parsing** – Validate phone numbers, determine carriers, and check region.  
4. **DNS & Reverse DNS** – Retrieve DNS records (A, CNAME, MX, NS) and PTR records.  
5. **Email Lookup** – Check MX records, validate format, parse email headers for IP addresses, and more.
6. **Email Breach Search** - Checks Have I Been Pwned to determine if an email address has been compromised.
7. **Email Header Analysis** - Analyzes an email header and extracts data.
8. **Person Search** - Look up public details about a person.   
9. **WHOIS Lookup** – Fetch domain registration details.  
10. **Password Strength Check** – Rate your password’s strength based on multiple criteria.
11. **Username Search** - Checks websites for account details, with a different approach compared to the Deep Account Search
12. **Reverse Phone Search** - Gets references from a number and extracts data from Google.
13. **Robots.txt / Sitemap.xml Check** - Finds a websites robots.txt and Sitemp.xml files.
14. **SSL Certificate Search** - Finds a webpage's SSL certificate information 
15. **DNSBL Search** - Gets blacklist information on a URL
16. **Website Metadata Fetch** - Retrieves meta tags and more from a website.
17. **Travel Risk Search** - Provides a detailed, 40 parameter analysis of a geographical location.
18. **Botometer Search** - Helps identify possible X/Twitter bots. The lower the score, the lower probability it is not a bod. A higher score indicates a higher probability that the account is a bot.
19. **Business Search** - Provides details about a business.
20. **Hudson Rock Email Search** - Searches for an email infected with an infostealer.
21. **Hudson Rock Username Search** - Searches for a username infected with an infostealer.
22. **Hudson Rock Domain Search** - Searches for a domain infected with an infostealer.
23. **Hudson Rock IP Address Search** - Searches for an IP address infected with an infostealer.
24. **Fact Check Search** - Verifies user inputted data.
25. **Relationship Search** - Analyzes relationships between people and entities.
26. **File Metadata Search** - Analyzes metadata from various file types.
27. **Subdomain Search** - Checks a domain for subdomains.
28. **Domain Search** - Domain info through Hunter.
29. **Email Search** - Email info search through Hunter.
30. **Email Verify** - Verifies an email through Hunter.
31. **Company Search** - Gets company info through Hunter.
32. **Person Info Search** - Retrieves person info through Hunter.
33. **Combined Search** - Performs a combined enrichment.
34. **Email Search** - Does a reverse email search through CastrickClues.
35. **Domain Search** - Performs a VirusTotal check on a domain.
36. **Malice Search** - Identifies potential malicious content based on text input.
37. **Supply / Vendor Search** - Finds information about companies that are suppliers or vendors.
38. **Business Reputation Search** - Gives details about the reputation of a business.
39. **Wayback Machine Search** - Allows the user to view archived versions of a website.
40. **Port Scan** - Scans a domain for open ports.
41. **Bulk CSV Search** - Extracts IP information from a CSV file.
42. **Vulnerability Search** - Displays data on known vulnerabilities by keyword.
43.  **Phone Leak Search** - Enquires whether a phone number is associated with an information leak.
44.  **AES Encryption / AES Decryption** - Encrypts plaintext with AES-256-CBC. Decrypts ciphertext if the correct key and IV is used.
45.  **Email Intelligence Search** - Retrieves public information from a provided email.
46.  **Website Search** - Extracts contact information from a domain / URL.
47.  **Reddit User Search** - Checks if a user has a Reddit account.
48.  **TikTok User Search** - Checks if a user is on TikTok.
49.  **TrueCaller Search** - Checks if a user is using Truecaller.
50.  **Sex Offender Search** - Identifies sex offenders by name.
51.  **WhatsApp Search** - Verifies whether a phone number has a WhatsApp account.
52.  **Skip Trace Search (Name, ID)** - Fetches details about a person by searching a name, or searching an ID number from the name search.
53.  **Ship Search** - Shows data about a ship by MMSI number. Shows information of a ship from a location.
54.  **Aircraft Search** - Retrieves aircraft data by location. Retrieves aircraft data by call sign.
55.  **Predicta Person Search** - Gives thorough information about a person using Predicta.
56. **Theme/Color Settings** – Adjust console output color.

57. **RapidAPI Services you need to subscribe to:

-https://rapidapi.com/softrix-technologies-dnschecker/api/mac-address-lookup1

-https://rapidapi.com/letscrape-6bRBa3QguO5/api/reverse-image-search1

-https://rapidapi.com/acelogicgaming/api/osint-tool-investigation

-https://rapidapi.com/Exerra/api/exerra-phishing-check

-https://rapidapi.com/osint-org-osint-org-default/api/x-checker

-https://rapidapi.com/do3t/api/truecaller-data2

-https://rapidapi.com/Canssens/api/identity-generator

-https://rapidapi.com/IgorMicrobilt/api/find-criminal-records-api

-https://rapidapi.com/OSoMe/api/botometer-pro

-https://rapidapi.com/rustychapin/api/known-vulnerability-search

-https://rapidapi.com/breachbeach1/api/phone-leak-search

-https://rapidapi.com/inutil-inutil-default/api/whatsapp-osint

-https://rapidapi.com/apicodex-apis/api/email-intelligence-api


(It's possible I may have missed one or two, if you're having trouble, contact me, or post in the discussion etc)

## Installation
1. **Clone the Repository (or download the zip)**:
    
    git clone https://github.com/Clats97/ClatScope.git
    
2. **Install Dependencies**:
    Open command prompt and write:

pip install requests pystyle phonenumbers dnspython email-validator beautifulsoup4 lxml python-whois tqdm openai python-magic Pillow PyPDF2 openpyxl python-docx python-pptx mutagen tinytag


 3. **Run the Script**:
    Click on the Python file or open it in Visual Studio Code 
    
## Usage
When you run the script, it will present you with a menu. Simply type the number corresponding to the function you wish to use, and follow the on-screen prompts. For example:

- **IP Info Search** – Option [1]
- **Deep Account Search** – Option [2]
- **DNS Search** – Option [4]
- etc.

- **IN ORDER FOR THE PASSWORD STRENGTH ANALYZER TO WORK PROPERLY, YOU MUST OPEN CLATSCOPE INFO TOOL IN THE FOLDER THAT HAS "PASSWORDS.TXT"**

- You will need to enter your own Google Custom Search, OpenAI, Botometer, Perplexity & Have I been Pwned API key to use all the features in this tool (unless you subscribe to the above mentioned service).
- If you want to use the password strength checker against a dictionary or known common-passwords file, place your dictionary file as passwords.txt in the same directory as the script. There is already a dictionary file in the installation package with millions of common passwords.
- The script references a Google Custom Search API key (API_KEY, CX, and CLIENT_ID), an OpenAI API key, a Perplexity API key, a Botometer API key, and HIBP API key. If you want to use the features that query external services (like Google search or HIBP), you must obtain valid keys and place them in the script.
- **Important:** If you do not have valid API keys, the related external queries (e.g. person search, reverse phone lookup, business search, travel risk search, Botometer search) will fail or return errors.

**THIS TOOL IS NOT PERFECT. THERE IS STILL ROOM FOR IMPROVEMENT, AND I AM WORKING ON ADDING NEW FEATURES AND REFINEMENTS. SOMETIMES A USERNAME SEARCH WILL RESULT IN A FALSE POSITIVE AND/OR THE URL WILL NOT RESOLVE. IT HAS BEEN TESTED AND IS ACCURATE, BUT NOT 100% ACCURATE. VERIFY THE OUTPUTS IF YOU ARE NOT SURE.**

## Contributing
1. Fork this repository`
2. Create a new Pull Request
3. Email me at skyline92x@pm.me for feature requests or ideas.

I welcome any improvements or additional OSINT features!

## License
This project is released under the Apache 2.0 License.

Copyright 2025 Joshua M Clatney (Clats97) All Rights Reserved

**DISCLAIMER: This project comes with no warranty, express or implied. The author is not responsible for abuse, misuse, or vulnerabilities. Please use responsibly and ethically in accordance with relevant laws, regulations, legislation and best practices.**
