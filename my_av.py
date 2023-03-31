#!/usr/bin/env python3
import math
import string
import re

protocol = "http://"
subdomain = "www"

def length(len1, len2):
    return len1 / len2

def levenshtein_distance(s1, s2):
    m = len(s1)
    n = len(s2)
    d = [[0 for x in range(n + 1)] for y in range(m + 1)]
    max_length = max(len(s1), len(s2))

    for i in range(m + 1):
        d[i][0] = i
    for j in range(n + 1):
        d[0][j] = j

    for j in range(1, n + 1):
        for i in range(1, m + 1):
            if s1[i - 1] == s2[j - 1]:
                d[i][j] = d[i - 1][j - 1]
            else:
                d[i][j] = 1 + min(d[i - 1][j], d[i][j - 1], d[i - 1][j - 1])

    return d[m][n]

def typos(domain):
    domains = ["facebook.com", "chat.whatsapp.com", "en.wikipedia.org",
               "youtube.com", "instagram.com", "paypal.com",
               "itunes.apple.com", "apple.com", "appleid.apple.co",
               "apps.facebook.com", "amazon.com", "google.com",
               "drive.google.com", "groups.google.com", "verify-paypal.com"]
    count = 0
    for i in range(len(domains)):
        if domains[i] in domain:
            if abs(len(domain) - len(domains[i])) > 10:
                return 1
        dist = levenshtein_distance(domain, domains[i])
        if dist >= 1 and dist <= 2:
            return 1
    return 0


def has_malicious_extension(link):
    extension = [".exe", ".dat", ".doc", ".ru", ".ke", ".cc", ".m", ".m68k",
                 ".cl/login", ".bat", ".png", ".pl", ".css", ".arm", ".sh",
                 ".32", ".ru/", "x86", ".co", ".arm7", ".pdf", ".i", ".pm",
                 ".arm6", ".jpg", ".bin", ".dz", ".arm5", ".net", ".pw",
                 "mips", ".mpsl", ".cf", ".br", ".download", ".spc", ".ppc",
                 ".fuku", ".ga", ".org", ".com", "Mozi.m", ".m68k", "/spc",
                 "/gate.php", "/file.php", "/signin", ".csv"]
    for i in range(len(extension)):
        if extension[i] in link:
            pos = len(link) - len(extension[i])
            if link[pos:] == extension[i]:
                return 1
    return 0

def special_character_domain(domain):
    special_characters = [".", "-"]
    count = 0
    for i in range(len(special_characters)):
        count = 0
        for j in range(len(domain)):
            if domain[j] in special_characters[i]:
                count += 1
        if count >= 4 and i == 0:
            return 1
        if count >= 3 and i == 1:
            return 1
    return 0

def special_words_link(link):
    special_words = ["verify", ".login", "security.", "signin", "e=com",
                     "/bin", "admin/"]
    for i in range(len(special_words)):
        if special_words[i] in link:
            return 1
    return 0

def task1():
    malicious = 0
    filename = ""
    link = ""
    domains = []
    domain = ""
    nr_letters = 0
    n = 0
    in_file = open("data/urls/domains_database", "r")
    for line in in_file:
        domains.append(line.strip())
        n += 1
    in_file.close()
    fp = open("data/urls/urls.in", "r")
    if not fp:
        return
    out = open("urls-predictions.out", "w")
    if not out:
        return
    for line in fp:
        malicious = 0
        link = line.strip()
        if has_malicious_extension(link):
            malicious = 1
        if special_words_link(link):
            malicious = 1
        p = link
        if protocol in p:
            p = p[len(protocol):]
        if subdomain in p:
            p = p[len(subdomain):]
            if p[0] != '.':
                malicious = 1
        q = p.find('/')
        if q == -1:
            q = len(link) - 1
        domain = p[:q]
        if special_character_domain(domain):
            malicious = 1
        if typos(domain):
            malicious = 1
        nr_letters = sum(i.isdigit() for i in domain)
        if nr_letters >= 0.35 * len(domain):
            malicious = 1
        for i in range(n):
            if domains[i] in link:
                malicious = 1
        out.write(str(malicious) + '\n')
    fp.close()
    out.close()

def check_bruteforce(data, n):
    sum = 0
    time_string = data[4]
    time_parts = re.split(r'[^0-9]', time_string)
    time_parts = list(filter(None, time_parts))
    days = int(time_parts[0])
    hours = int(time_parts[1])
    mins = int(time_parts[2])
    secs = int(time_parts[3])
    if len(time_parts) > 4:
        milisecs = int(time_parts[4])
        if int(milisecs) >= 1000:
            sum = 1
    sum += 86400.0 * days + 3600.0 * hours + 60 * mins + secs
    if sum > 0.0 and float(data[n - 1]) > 570.0:
        if int(data[5]) > 45 or int(data[6]) > 45:
            return 1
    return 0

def check_cryptominer(data, malign):
    if data[9] == "0" and data[10] == "0" and data[11] == "0":
        return 1
    return 0

def check_safe_ip(data):
    safe_ips = ["255.255.255.255", "ff02::16", "8.8.8.8",
                "239.255.255.250", "36.91.114.86"]
    if data[2] in safe_ips:
        return 1
    return 0

def task2():
    traffic = "data/traffic/traffic.in"
    out = "traffic-predictions.out"
    with open(traffic, "r") as in_file, open(out, "w") as out_file:
        line = in_file.readline()
        for line in in_file:
            malign = 0
            data = line.strip().split(',')
            if check_bruteforce(data, len(data)):
                malign = 1
            if check_cryptominer(data, malign):
                malign = 1
            if check_safe_ip(data):
                malign = 0
            out_file.write(f"{malign}\n")

def main():
    task1()
    task2()

if __name__ == '__main__':
    main()