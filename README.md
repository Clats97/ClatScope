# ClatScope Info Tool & ClatScope Info Tool Mini

ClatScope Mini is a variant of ClatScope Info Tool that does not require any API keys and will work out of the box. It was released 2025-05-18.

ClatScope Info Tool – A versatile OSINT utility for retrieving geolocation, DNS, WHOIS, phone, email, usernames, person related data, password strength, data breach information and more. Perfect for investigators, pentesters, or anyone looking for a quick reconnaissance script. **This script requires API keys for some functions (Perplexity, Have I Been Pwned, Hunter, Hudson Rock, Castrick, Predicta, RapidAPI). If you do not want to set up your own API keys, below there is a subscription service. Otherwise, you are free to use this script as you see fit.**

![clatscopeinfo](https://github.com/user-attachments/assets/e0060201-2e10-41c2-b892-ba73726e1209)

![clatscopecli](https://github.com/user-attachments/assets/85a17e63-8a81-4405-ad47-846367c1c923)

**DONT WANT TO SET UP YOUR API KEYS TO GET FULL FUNCTIONALITY OF CLATSCOPE INFO TOOL? STARTING JANUARY 12, 2024 A SUBSCRIPTION SERVICE IS AVAILABLE. YOU WILL BE PROVIDED WITH A CUSTOM SCRIPT WITH API KEYS THAT LOGS IP ADDRESS, USER AGENT, USAGE, AND OTHER DETAILS TO ENSURE THERE IS NO UNAUTHORIZED ACCESS OR MISUSE. SHARING IS PROHIBITED AND WILL RESULT IN AN IMMEDIATE REVOCATION OF THE KEY. TURN OFF YOUR VPN WHEN USING IT TO PREVENT AN AUTOMATIC BAN FOR IMPOSSIBLE TRAVEL / SHARING. ALL API KEYS ARE PROTECTED BY WAAP & CLOUDFLARE API SECURITY. YOUR SUBSCRIPTION IS VALID FOR 30 DAYS. IF YOU RENEW, YOU WILL BE ISSUED A NEW KEY AT THE START OF YOUR RENEWAL. KEYS ARE ROTATED MONTHLY AND ARE SINGLE USE AND MONITORED. EMAIL SKYLINE92X@PM.ME FOR DETAILS.** 

**SUBSCRIPTION LINKS:**

**TIER 1: https://buymeacoffee.com/clats97/e/357348.**

**TIER 2: https://buymeacoffee.com/clats97/e/361894**

**NO REFUNDS**

ClatScope is an OSINT tool that performs various lookups and analyzes provided data.

Throughout the script, a textual UI is presented, prompting the user for inputs (e.g., IP address, phone number). Results are printed in styled ASCII frames using the pystyle library for aesthetics.

**Version:** 1.17 (2025-05-18)
**Author:** Joshua M Clatney aka Clats97 (Ethical Pentesting Enthusiast)

## Description
ClatScope Info Tool is an all-in-one OSINT (Open-Source Intelligence) utility script that queries public APIs, DNS records, and other online resources to gather and display information about IPs, domains, emails, phone numbers, and more. You will need to enter the required API keys to take advantage of all the features ClatScope Info Tool v1.15 has to offer.

## Features

---

1. **IP Address Search** – Extracts IP geolocation, ISP, and provides a Google Maps link.
2. **Deep Account Search** – Checks over 250 websites for the existence of a given username.
3. **Phone Number Parsing** – Validates phone numbers, determines carriers, and checks region.
4. **DNS Record Search** – Retrieves DNS records (A, CNAME, MX, NS) for a given domain.
5. **Email MX Search** – Checks MX records to verify email server configuration.
6. **Person Name Search** – Looks up public details about a person.
7. **Reverse DNS Search** – Retrieves PTR records to map IPs back to host names.
8. **Email Header Search** – Analyzes email headers to extract data and originating IPs.
9. **Email Breach Search** – Checks Have I Been Pwned to see if an email was compromised.
10. **WHOIS Search** – Fetches domain registration and ownership details.
11. **Password Analyzer** – Rates your password’s strength based on multiple security criteria.
12. **Username Search** – Checks websites for account details, different methodology from Deep Account Search.
13. **Reverse Phone Search** – Gets references for a phone number, including search engine extraction.
14. **SSL Search** – Retrieves SSL certificate details from a webpage.
15. **Web Crawler Search** – Finds robots.txt and sitemap.xml files for a website.
16. **DNSBL Search** – Checks if an IP/domain appears on DNS blacklists.
17. **Web Metadata Search** – Retrieves meta tags and structured data from a webpage.
18. **Travel Risk Search** – Provides a 40-parameter detailed travel risk assessment for a location.
19. **Botometer Search** – Checks X/Twitter accounts for bot likelihood and scoring.
20. **Business Search** – Provides general information and verification about a business.
21. **HR Email Search** – Checks if an email is compromised by an infostealer (Hudson Rock).
22. **HR Username Search** – Checks if a username is linked to infostealer infection (Hudson Rock).
23. **HR Domain Search** – Checks if a domain has infostealer infection data (Hudson Rock).
24. **HR IP Search** – Checks if an IP address is associated with infostealer infections (Hudson Rock).
25. **Fact Check Search** – Analyzes and verifies the truthfulness of user-inputted text.
26. **Relationship Search** – Maps and analyzes relationships between people, businesses, or entities.
27. **File Metadata Search** – Extracts metadata from files (images, documents, media, etc.).
28. **Subdomain Search** – Finds subdomains related to a main domain.
29. **Domain Search (Hunter.io)** – Retrieves domain information and email sources using Hunter.io.
30. **Email Search (Hunter.io)** – Searches for emails associated with a domain via Hunter.io.
31. **Email Verify Search (Hunter.io)** – Verifies the deliverability of an email through Hunter.io.
32. **Company Search (Hunter.io)** – Enriches and fetches company information through Hunter.io.
33. **Person Info Search (Hunter.io)** – Retrieves detailed person enrichment through Hunter.io.
34. **Combined Search (Hunter.io)** – Aggregates multiple enrichment results using Hunter.io.
35. **Email Search (CastrickClues)** – Performs reverse email lookup for in-depth information.
36. **Virus Search (VirusTotal)** – Fetches a VirusTotal malware report for a domain.
37. **Malice Search** – Identifies potential malicious content or scams in text input.
38. **Supply/Vendor Search** – Provides a risk assessment and information on suppliers/vendors.
39. **Business Rep Search** – Generates a business reputation overview.
40. **Wayback Search** – Retrieves historical snapshots from the Internet Archive’s Wayback Machine.
41. **Port Scan Search** – Scans a domain or IP for open and vulnerable ports.
42. **Bulk CSV Search** – Performs multiple checks in bulk using uploaded CSV files.
43. **Phone Leak Search** – Checks if a phone number appears in known leaks or breaches.
44. **AES Encryption** – Encrypts plaintext using AES-256-CBC with an IV for secure storage.
45. **AES Decryption** – Decrypts ciphertext using AES-256-CBC, requiring correct key and IV.
46. **Email Intel Search** – Retrieves public information and reputation data for an email.
47. **TikTok User Search** – Fetches TikTok account information by username.
48. **Truecaller Search** – Retrieves phone number details using Truecaller database.
49. **Skip Trace Search (Name)** – Provides skip tracing details by searching for a person's name.
50. **Skip Trace Search (ID)** – Provides skip tracing details by searching an ID or related identifier.
51. **Ship Search v1 (MMSI)** – Looks up ship data by MMSI number.
52. **Ship Search v2 (Radius/Location)** – Looks up ship data by geographical location (radius search).
53. **Aircraft Search v1 (Location)** – Retrieves aircraft data by searching a location.
54. **Aircraft Search v2 (Callsign)** – Retrieves aircraft data by searching by callsign.
55. **Predicta Search** – Provides comprehensive personal information via Predicta.
56. **Crim Record Search** – Retrieves a criminal record check from a small (US-only) database.
57. **Identity Generator** – Generates a false identity for privacy and obfuscation purposes.
58. **Virtual Phone Search** – Verifies if a phone number is virtual/VoIP.
59. **MAC Address Search** – Retrieves detailed info on MAC addresses and associated IPs.
60. **AutoScan Search** – Produces an in-depth automated OSINT scan report.
61. **Conflict Search** – Compares and reports on potential conflicts between entities/people.
62. **Detailed IP Search (IPStack)** – Extracts detailed IP information using the IPStack API.
63. **Verifone Search (Phone Validation v1)** – Provides detailed phone number validation.
64. **NumVerify Search (Phone Validation v2)** – Provides additional phone validation via NumVerify.
65. **General OSINT Search** – Aggregates general open-source data on a target individual.
66. **Contact Info Search** – Extracts contact info related to a target individual.
67. **Instagram Search** – Checks if an email is used to register an Instagram account.
68. **Similar Face Search** – Analyzes two images to determine if they depict the same person.
69. **Reverse Image Search** – Finds reference sources for a given photograph.
70. **Reddit User Search** – Checks if a Reddit account exists for the provided username.
71. **X/Twitter Search** – Verifies if an email is registered on X (Twitter).

---

## Installation
1. **Clone the Repository (or download the zip)**:
    
    git clone https://github.com/Clats97/ClatScope.git
    
2. **Install Dependencies**:
    Open command prompt and write:

pip install phonenumbers openai requests pystyle dnspython email-validator beautifulsoup4 whois tqdm magic pillow PyPDF2 openpyxl python-docx pptx mutagen tinytag

 3. **Run the Script**:
    Click on the Python file or open it in Visual Studio Code. 
    
## Usage
When you run the script, it will present you with a menu. Simply type the number corresponding to the function you wish to use, and follow the on-screen prompts. For example:

- **IP Info Search** – Option [1]
- **Deep Account Search** – Option [2]
- **DNS Search** – Option [4]
- etc.

- **IN ORDER FOR THE PASSWORD STRENGTH ANALYZER TO WORK PROPERLY, YOU MUST OPEN CLATSCOPE INFO TOOL IN THE FOLDER THAT HAS "PASSWORDS.TXT"**

- You will need to enter your own Perplexity, Have I Been Pwned, Hunter, Hudson Rock, Castrick, Predicta, RapidAPI API keys to use all the features in this tool (unless you subscribe to the above mentioned service).
- If you want to use the password strength checker against a dictionary or known common-passwords file, place your dictionary file as passwords.txt in the same directory as the script. There is already a dictionary file in the installation package with millions of common passwords.
- **Important:** If you do not have valid API keys, the related external queries (e.g. person search, reverse phone lookup, business search, travel risk search, Botometer search) will fail or return errors.

**THIS TOOL IS NOT PERFECT. THERE IS STILL ROOM FOR IMPROVEMENT, AND I AM WORKING ON ADDING NEW FEATURES AND REFINEMENTS. SOMETIMES A USERNAME SEARCH WILL RESULT IN A FALSE POSITIVE AND/OR THE URL WILL NOT RESOLVE. IT HAS BEEN TESTED AND IS ACCURATE, BUT NOT 100% ACCURATE. VERIFY THE OUTPUTS IF YOU ARE NOT SURE.**

## Contributing
1. Fork this repository`
2. Create a new Pull Request
3. Email me at skyline92x@pm.me for feature requests or ideas.

I welcome any improvements or additional OSINT features!

**Author**

Joshua M Clatney (Clats97)

Ethical Pentesting Enthusiast

Copyright 2024-2025 Joshua M Clatney (Clats97) All Rights Reserved

**DISCLAIMER: This project comes with no warranty, express or implied. The author is not responsible for abuse, misuse, or vulnerabilities. Please use responsibly and ethically in accordance with relevant laws, regulations, legislation and best practices.**
