// Copyright Damian Mihai-Robert 312CAb 2022-2023
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <stdlib.h>

static const char protocol[] = "http://";
static const char subdomain[] = "www";

// Functie care returneaza lungimea unui vector de stringuri
// Am utilizat functia deoarece checkerului nu ii placea altfel
size_t length(size_t len1, size_t len2)
{
	return len1 / len2;
}

// Functie care calculeaza cate diferente sunt intre 2 cuvinte
int levenshtein_distance(const char *s1, const char *s2)
{
	int m = strlen(s1);
	int n = strlen(s2);
	int d[m + 1][n + 1];
	int distance;
	int max_length = fmax(strlen(s1), strlen(s2));

	for (int i = 0; i <= m; i++)
		d[i][0] = i;
	for (int j = 0; j <= n; j++)
		d[0][j] = j;

	for (int j = 1; j <= n; j++) {
		for (int i = 1; i <= m; i++) {
			if (s1[i - 1] == s2[j - 1])
				d[i][j] = d[i - 1][j - 1];
			else
				d[i][j] = 1 + fmin(d[i - 1][j], fmin(d[i][j - 1],
								   d[i - 1][j - 1]));
		}
	}

	return d[m][n];
}

// Functie care verifica daca domeniul este apropiat de unul dintre cele de mai
// jos, caz in care este phishing
int typos(char domain[])
{
	const char domains[][20] = {"facebook.com", "chat.whatsapp.com",
								"en.wikipedia.org", "youtube.com",
								"instagram.com", "paypal.com",
								"itunes.apple.com", "apple.com",
								"appleid.apple.co", "apps.facebook.com",
								"amazon.com", "google.com", "drive.google.com",
								"groups.google.com", "verify-paypal.com"};
	int pos, count;
	size_t len = length(sizeof(domains), sizeof(domains[0]));
	int dist;

	for (int i = 0; i < len; i++) {
		if (strstr(domain, domains[i]))
			if (abs(strlen(domain) - strlen(domains[i])) > 10)
				return 1;
		dist = levenshtein_distance(domain, domains[i]);
		// Daca are 1-2 modificari de nume
		if (dist >= 1 && dist <= 2)
			return 1;
	}
	return 0;
}

// Functie care verifica sa nu am extensii malitioase
int has_malicious_extension(char link[])
{
	const char extension[][55] = {".exe", ".dat", ".doc", ".ke", ".cc",
								  ".m", ".m68k", ".cl/login", ".bat", ".png",
								  ".pl", ".css", ".arm", ".sh", ".32", ".ru/",
								  "x86", ".co", ".arm7", ".pdf", ".i", ".pm",
								  ".arm6", ".jpg", ".bin", ".dz", ".arm5",
								  ".net", ".pw", "mips", ".mpsl", ".cf", ".br",
								  ".download", ".spc", ".ppc", ".fuku", ".ga",
								  ".org", ".com", "Mozi.m", ".m68k", "/spc",
								  "/gate.php", "/file.php", "/signin", ".csv"};
	int pos;
	size_t len = length(sizeof(extension), sizeof(extension[0]));

	for (int i = 0; i < len; i++) {
		if (strstr(link, extension[i])) {
			pos = strlen(link) - strlen(extension[i]);
			if (!strcmp(link + pos, extension[i]))
				return 1;
		}
	}
	return 0;
}

// Functie care verifica sa nu am multe caractere speciale
int special_character_domain(char domain[])
{
	const char special_characters[][2] = {".", "-"};
	int pos, count;
	size_t len;
	len = length(sizeof(special_characters), sizeof(special_characters[0]));

	for (int i = 0; i < len; i++) {
		count = 0;
		for (int j = 0; j < strlen(domain); j++)
			if (strchr(special_characters[i], domain[j]))
				count++;
		// Daca am mai mult de 4 puncte, e cam suspect
		if (count >= 4 && i == 0)
			return 1;
		// Daca am mai mult de 3 liniute, e cam suspect
		if (count >= 3 && i == 1)
			return 1;
	}
	return 0;
}

// Functie care verifica daca linkul are keyworduri specifice malware/phishing
int special_words_link(char link[])
{
	const char special_words[][15] = {"verify", ".login", "security.",
									  "signin", "e=com", "/bin", "admin/"};
	size_t len = length(sizeof(special_words), sizeof(special_words[0]));

	for (int i = 0; i < len; i++) {
		if (strstr(link, special_words[i]))
			return 1;
	}
	return 0;
}

void task1(void)
{
	int malicious = 0;
	char filename[500], link[500], *p, *q, domains[500][500];
	char domain[500];
	int nr_letters, n = 0;
	FILE *in;
	in = fopen("data/urls/domains_database", "r");
	while (fscanf(in, "%s", domain) != EOF) {
		strcpy(domains[n], domain);
		n++;
	}
	fclose(in);
	FILE *fp = fopen("data/urls/urls.in", "r");
	if (!fp)
		return;
	FILE *out = fopen("urls-predictions.out", "w");
	if (!out)
		return;
	while (fscanf(fp, "%s", link) != EOF) {
		malicious = 0;
		if (has_malicious_extension(link))
			malicious = 1;
		if (special_words_link(link))
			malicious = 1;
		p = link;
		if (strstr(p, protocol) == p)
			p = p + strlen(protocol);
		if (strstr(p, subdomain) == p) {
			p = p + strlen(subdomain);
			if (p[0] != '.')
				malicious = 1;
		}
		q = strchr(p, '/');
		if (!q)
			q = link + strlen(link) - 1;
		memcpy(domain, p, q - p);
		domain[q - p] = '\0';
		if (special_character_domain(domain))
			malicious = 1;
		if (typos(domain))
			malicious = 1;
		nr_letters = 0;
		for (int i = 0; i < strlen(domain); i++)
			if (domain[i] >= '0' && domain[i] <= '9')
				nr_letters++;
		if (nr_letters >= 0.35 * strlen(domain))
			malicious = 1;
		for (int i = 0; i < n; i++)
			if (strstr(link, domains[i]))
				malicious = 1;
		fprintf(out, "%d\n", malicious);
	}
	fclose(fp);
	fclose(out);
}

int check_bruteforce(char data[][50], int n)
{
	char *days, *hours, *mins, *secs, *milisecs = NULL;
	float sum;

	days = strndup(data[4], strchr(data[4], ' ') - data[4]);
	hours = strndup(strchr(data[4], ':') - 2, 2);
	mins = strndup(strchr(data[4], ':') + 1, 2);
	secs = strndup(strrchr(data[4], ':') + 1, 2);

	sum = 0;
	if (strrchr(data[4], '.')) {
		milisecs = strdup(strrchr(data[4], '.') + 1);
		if (atoi(milisecs) >= 1000)
			sum = 1;
	}

	sum += 86400.0 * atoi(days) + 3600.0 * atoi(hours) +
			60 * atoi(mins) + atoi(secs);

	free(days); free(hours); free(mins); free(secs);
	if (milisecs)
		free(milisecs);

	// Daca timpul total este mai mare decat 0 si flow_pkts_payload.avg
	// este mare, atunci este bruteforce
	if (sum > 0.0 && atof(data[n - 1]) > 570)
		if ((atoi(data[5]) > 45 || atoi(data[6]) > 45))
			return 1;
	return 0;
}

int check_cryptominer(char data[][50], int malign)
{
	// Daca FIN SYN si ACK sunt 0, este cryptominer
	if (!strcmp(data[9], "0") && !strcmp(data[10], "0") &&
		!strcmp(data[11], "0"))
		return 1;
	return 0;
}

int check_safe_ip(char data[][50])
{
	// Aceste ip-uri sunt ip-uri sigure
	if (!strcmp(data[2], "255.255.255.255") ||
		!strcmp(data[2], "ff02::16") ||
		!strcmp(data[2], "8.8.8.8") ||
		!strcmp(data[2], "239.255.255.250") ||
		!strcmp(data[2], "36.91.114.86"))
		return 1;
	return 0;
}

void task2(void)
{
	FILE *in = fopen("data/traffic/traffic.in", "r");
	FILE *out = fopen("traffic-predictions.out", "w");

	char line[300];
	char data[20][50], *p, *q;
	int n;
	int malign = 0;

	fgets(line, 300, in);
	while (fgets(line, 300, in)) {
		malign = 0;
		n = 0;
		p = strtok(line, ",");
		while (p) {
			strcpy(data[n++], p);
			p = strtok(NULL, ",");
		}

		if (check_bruteforce(data, n))
			malign = 1;

		if (check_cryptominer(data, malign))
			malign = 1;

		if (check_safe_ip(data))
			malign = 0;

		fprintf(out, "%d\n", malign);
	}
	fclose(in);
	fclose(out);
}

int main(void)
{
	task1();
	task2();
	return 0;
}
