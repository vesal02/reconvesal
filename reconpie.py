import requests, socket, re, whois, subprocess, os
from bs4 import BeautifulSoup
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup

def generate_sitemap(domain, depth=2, max_workers=10):
    visited, to_visit = set(), [(domain, 0)]
    links = set()
    headers = {'User-Agent': 'Mozilla/5.0'}

    def fetch_links(url, level):
        if level > depth or url in visited:
            return []
        try:
            response = requests.get('https://' + url, headers=headers, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            local_links = []
            for tag in soup.find_all('a', href=True):
                href = tag['href']
                if href.startswith('/'):
                    href = domain + href
                if domain in href:
                    clean = href.replace('http://', '').replace('https://', '').split('/')[0]
                    if clean not in visited:
                        local_links.append((clean, level + 1))
                        links.add(clean)
            return local_links
        except:
            return []

    while to_visit:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(fetch_links, url, level): (url, level) for url, level in to_visit}
            to_visit = []
            for future in as_completed(future_to_url):
                new_links = future.result()
                visited.add(future_to_url[future][0])
                to_visit.extend(new_links)

    return list(links)

def resolve_subdomain(sub):
    try:
        socket.gethostbyname(sub)
        return sub
    except:
        return None

def find_subdomains(domain, wordlist='subdomains.txt'):
    with open(wordlist) as file:
        subs = [line.strip() + '.' + domain for line in file if line.strip()]
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(resolve_subdomain, subs))
    return [res for res in results if res]

def fetch_title(sub):
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get('https://' + sub, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else 'No Title'
        return (sub, response.status_code, title)
    except Exception as e:
        return (sub, 'Error', str(e))

def fetch_status_title(subdomains):
    with ThreadPoolExecutor(max_workers=50) as executor:
        return list(executor.map(fetch_title, subdomains))

def resolve_ip(sub):
    try:
        return (sub, socket.gethostbyname(sub))
    except:
        return (sub, 'Unresolved')

def resolve_ips(subdomains):
    with ThreadPoolExecutor(max_workers=50) as executor:
        return dict(executor.map(resolve_ip, subdomains))

def check_ports(sub_ip):
    sub, ip = sub_ip
    ports_to_check = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 8080]
    open_ports = []
    if ip == 'Unresolved':
        return (sub, open_ports)
    for port in ports_to_check:
        try:
            sock = socket.create_connection((ip, port), timeout=1)
            sock.close()
            open_ports.append(port)
        except:
            continue
    return (sub, open_ports)

def scan_ports(ip_map):
    with ThreadPoolExecutor(max_workers=50) as executor:
        return dict(executor.map(check_ports, ip_map.items()))

def extract_emails_phones(domain):
    emails, phones = set(), set()
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get('https://' + domain, headers=headers, timeout=5)
        text = response.text
        emails = set(re.findall(r'[\w\.-]+@[\w\.-]+', text))
        phones = set(re.findall(r'[+]?\d[\d\-\s]{7,}\d', text))
    except:
        pass
    return list(emails), list(phones)

def get_whois(domain):
    try:
        info = whois.whois(domain)
        return str(info)
    except:
        return 'WHOIS Lookup Failed'

def run_reconpie(domain):
    output = {}

    sitemap = generate_sitemap(domain)
    output['Sitemap Links'] = '\n'.join(sitemap)

    subdomains = find_subdomains(domain)
    output['Subdomains Found'] = '\n'.join(subdomains)

    status_title = fetch_status_title(subdomains)
    output['Status & Titles'] = '\n'.join([f"{s} - {c} - {t}" for s, c, t in status_title])

    ip_map = resolve_ips(subdomains)
    output['IP Addresses'] = '\n'.join([f"{s}: {i}" for s, i in ip_map.items()])

    ports = scan_ports(ip_map)
    output['Open Ports'] = '\n'.join([f"{s}: {', '.join(map(str, p))}" for s, p in ports.items()])

    emails, phones = extract_emails_phones(domain)
    output['Emails'] = '\n'.join(emails)
    output['Phone Numbers'] = '\n'.join(phones)

    output['WHOIS Info'] = get_whois(domain)

    return output



def improved_extract_emails_phones(domain, sitemap_links):
    import re
    import requests
    from bs4 import BeautifulSoup

    headers = {'User-Agent': 'Mozilla/5.0'}
    emails, phones = set(), set()

    for page in sitemap_links:
        try:
            url = f"https://{page}" if not page.startswith("http") else page
            response = requests.get(url, headers=headers, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text()

            found_emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)
            found_phones = re.findall(r'(?:(?:\+|00)\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d{3,4}[\s-]?\d{4}', text)

            emails.update(found_emails)
            phones.update(found_phones)
        except Exception:
            continue

    return list(emails), list(phones)

def run_reconpie(domain):
    output = {}

    sitemap = generate_sitemap(domain)
    output['Sitemap Links'] = '\n'.join(sitemap)

    subdomains = find_subdomains(domain)
    output['Subdomains Found'] = '\n'.join(subdomains)

    status_title = fetch_status_title(subdomains)
    output['Status & Titles'] = '\n'.join([f"{s} - {c} - {t}" for s, c, t in status_title])

    ip_map = resolve_ips(subdomains)
    output['IP Addresses'] = '\n'.join([f"{s}: {i}" for s, i in ip_map.items()])

    ports = scan_ports(ip_map)
    output['Open Ports'] = '\n'.join([f"{s}: {', '.join(map(str, p))}" for s, p in ports.items()])

    emails, phones = improved_extract_emails_phones(domain, sitemap)
    output['Emails'] = '\n'.join(emails)
    output['Phone Numbers'] = '\n'.join(phones)

    output['WHOIS Info'] = get_whois(domain)

    return output
