#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// numarul maxim de caractere dintr-un URL
#define MAX_CHARS 500
// numarul maxim de caractere al unei caracteristici a capturii de trafic
#define MAX_CHARS_DETAILS 50
struct url_structure {
	char *host;
	char *path;
};

struct traffic_structure {
	char *response_port;
	char *flow_duration;
	char *flow_pkts_payload;
	char *fwd_pkts_tot;
};

struct url_structure url;
struct traffic_structure traffic;
int i;

ssize_t url_size;
ssize_t line_size;
char *url_curent;
char *traffic_curent;
size_t buf_size;
unsigned int result;

void task1_part1(void)
{
	// se aloca memorie pentru URL-ul citit
	url.host = calloc(url_size + 1, sizeof(char));
	url.path = calloc(url_size + 1, sizeof(char));
	// initializare i cu 0
	i = 0;

	/* in urmatoarea bucla "while" se parcurge fiecare caracter al
	URL-ului analizat pana cand se ajunge la caracterul '/' de la path
	sau ':' de la port */
	while (url_curent[i] != '/' && url_curent[i] != ':' && i < url_size) {
		/* in "url.host[i]", la elementul al "i"-lea, se copiaza valoarea
		lui c[i] */
		url.host[i] = url_curent[i];
		// in "i" se pastreaza numarul de caractere a host-ului
		i++;
	}

    /* se deschide fisierul "domains_database" pentru a compara
    domeniul fiecarui URL din urls.in cu domeniile din baza de date;
    fisierul "domains_database" se deschide pentru fiecare
    URL din "urls.in" */
	FILE * fin_tests = fopen("data/urls/domains_database", "r");

    // in vectorul test_host se va stoca host-ul analizat din baza de date
	char test_host[MAX_CHARS];

    /* "result" - variabila in care se stocheaza raspunsul:
    0 - benign, 1 - malware sau phishing */
	result = 0;

    /* se citeste un domeniu din baza de date si daca acesta nu s-a gasit
    in URL-ul curent, se citeste urmatorul domeniu din baza de date */
	while ((fscanf(fin_tests, "%[^\n]%*c", test_host)) != EOF && result == 0) {
		/* daca host-ul URL-ului din url.in contine un domeniu din database,
		atunci result = 1, daca nu contine, atunci result = 0 */
		if (strstr(url.host, test_host))
			result = 1;
	}
	/* daca host-ul contine ".ru",
	atunci este sansa mare ca URL-ul sa nu fie benign */
	if (strstr(url.host, ".ru"))
		result = 1;

    /* se declara un contor k_c_p in care se afla
    numarul de cifre si puncte din host */
	unsigned int k_c_p = 0;
	for (int j = 0; j < strlen(url.host) - 1; j++) {
		if (url.host[j] >= 48 && url.host[j] <= 57 || url.host[j] == '.')
			k_c_p++;
	}

    // daca host-ul contine cel putin o cifra, result=1
	for (int j = 0; j < strlen(url.host) - 1; j++) {
		if (url.host[j] >= 48 && url.host[j] <= 57) {
			result = 1;
			break;
		}
	}

	// daca host-ul contine doar cifre si puncte, result = 1
	if (k_c_p == strlen(url.host) - 1)
		result = 1;

	// daca host-ul contine string-ul "ypa"
	if (strstr(url.host, "ypa"))
		result = 1;
	fclose(fin_tests);
}

void task1_part2(void)
{
	/* se gaseste fisierul cu extensie din calea URL-ului curent */
	// initializare j cu numarul de caractere a host-ului din URL
	unsigned int j = i;
	while (j < url_size) {
		/* se copiaza fiecare caracter din PATH-ul
		URL-ului in url.path */

		// in "i" se pastreaza numarul de caractere a URL-ului
		url.path[j - i] = url_curent[j];
		j++;
	}
	// initializare j cu 0
	j = 0;
	/* in pointerul "p" se stocheaza adresa ultimului '.' din
	"url.path", scopul fiind gasirea in URL a fisierului
	cu extensie, care poate fi daunator */
	char *p = NULL;
	p = strrchr(url.path, '.');
	/* daca PATH a URL-ului contine caracterul '.' (de la extensia unui
	fisier);
	daca contine, se iau decizii in functie de ultimul '.' din URL */
	if (strrchr(url.path, '.')) {
		/* in variabilele "c1".."c6" se pastreaza valoarea de adevar
		a fiecarei conditii */
		unsigned int c1 = 0, c2 = 0, c3 = 0, c4 = 0, c5 = 0, c6 = 0;
		// ultimele 4 caractere din "url.path" nu sunt html
		if (!(url.path[strlen(url.path) - 5] == 'h')) {
			if (!(url.path[strlen(url.path) - 4] == 't')) {
				if (!(url.path[strlen(url.path) - 3] == 'm')) {
					if (!(url.path[strlen(url.path) - 2] == 'l'))
						c1 = 1;
				}
			}
		}
		// urmatoarele 5 caractere de dupa ultimul punct gasit nu sunt html?
		if (!(p[1] == 'h' && p[2] == 't' && p[3] == 'm')) {
			if (!(p[4] == 'l' && p[5] == '?'))
				c2 = 1;
		}
		// ultimele 3 caractere din "url.path" nu sunt htm
		if (!(url.path[strlen(url.path) - 4] == 'h')) {
			if (!(url.path[strlen(url.path) - 3] == 't')) {
				if (!(url.path[strlen(url.path) - 2] == 'm'))
					c3 = 1;
			}
		}
		// urmatoarele 4 caractere de dupa ultimul punct gasit nu sunt htm?
		if (!(p[1] == 'h' && p[2] == 't' && p[3] == 'm' && p[4] == '?'))
			c4 = 1;
		// ultimele 3 caractere din "url.path" nu sunt php
		if (!(url.path[strlen(url.path) - 4] == 'p')) {
			if (!(url.path[strlen(url.path) - 3] == 'h')) {
				if (!(url.path[strlen(url.path) - 2] == 'p'))
					c5 = 1;
			}
		}
		// urmatoarele 4 caractere de dupa ultimul punct gasit nu sunt php?
		if (!(p[1] == 'p' && p[2] == 'h' && p[3] == 'p' && p[4] == '?'))
			c6 = 1;
		/* result = 1 daca toate conditiile au fost indeplinite
		result = 0, daca nu au fost indeplinite toate conditiile */
		result = c1 * c2 * c3 * c4 * c5 * c6;
	}
}

void task2_part1(void)
{
	/* se aloca memorie pentru detaliile de pe coloana "flow_duration"
	a capturii de trafic citita */
	traffic.flow_duration = calloc(MAX_CHARS_DETAILS, sizeof(char));
	i = 0;
	/* in k_virgule se afla numarul de virgule citite
	pana la "flow_duration" */
	unsigned int k_virgule = 0;
	while (k_virgule <= 3) {
		if (traffic_curent[i] == ',')
			k_virgule++;
		i++;
	}
	// lui j i se atribuie pozitia primului caracter din coloana analizata
	int j = i;
	while (traffic_curent[j] != ',') {
		/* in "traffic.flow_duration" se pastreaza valoarea
		de pe coloana "flow_duration" */
		traffic.flow_duration[j - i] = traffic_curent[j];
		j++;
	}
	/* in k_2p se afla numarul de caractere de ":" din "flow_duration"
	pentru a gasi secundele */
	unsigned int k_2p = 0;
	i = 0;
	while (k_2p <= 1) {
		if (traffic.flow_duration[i] == ':')
			k_2p++;
		i++;
	}
	// se incrementeaza i pentru a ajunge la unitatile de secunda
	i++;
	// daca "flow_duration" este mai mare de o secunda
	if (traffic.flow_duration[i] > '0')
		result = 1;

	/* se aloca memorie pentru detaliile de pe coloana
	"flow_pkts_payload.avg" a capturii de trafic citita */
	traffic.flow_pkts_payload = calloc(MAX_CHARS_DETAILS, sizeof(char));

	i = 0;
	/* in k_virgule se afla numarul de virgule citite
	pana la "flow_pkts_payload.avg" */
	k_virgule = 0;
	while (k_virgule <= 15) {
		if (traffic_curent[i] == ',')
			k_virgule++;
		i++;
	}
	/* in "traffic.flow_pkts_payload" se pastreaza valoarea
	de pe coloana "traffic.flow_pkts_payload.avg" */
	// lui j i se atribuie pozitia primului caracter din coloana analizata
	for (int j = i; j < line_size - 1; j++)
		traffic.flow_pkts_payload[j - i] = traffic_curent[j];

	/* se verifica daca lungimea sirului de caractere de pe coloana
	"flow_pkts_payload" este 3 și dacă acest sir este "0.0" */
	if (strlen(traffic.flow_pkts_payload) == 3) {
		if (traffic.flow_pkts_payload[0] == '0') {
			if (traffic.flow_pkts_payload[1] == '.') {
				if (traffic.flow_pkts_payload[2] == '0')
					result = 0;
			}
		}
	}
}

void task2_part2(void)
{
	/* se aloca memorie pentru detaliile de pe coloana fwd_pkts_tot
	a capturii de trafic citite */

	traffic.fwd_pkts_tot = calloc(MAX_CHARS_DETAILS, sizeof(char));

	/* se copiaza valoarea de pe coloana "fwd_pkts_tot"
	in traffic.fwd_pkts_tot */
	i = 0;
	/* in k_virgule se afla numarul de virgule citite
	pana la "fwd_pkts_tot" */
	unsigned int k_virgule = 0;
	while (k_virgule <= 4) {
		if (traffic_curent[i] == ',')
			k_virgule++;
		i++;
	}
	// lui j i se atribuie pozitia primului caracter din coloana analizata
	int j = i;
	while (traffic_curent[j] != ',') {
		/* in "traffic.fwd_pkts_tot" se pastreaza valoarea
		de pe coloana "fwd_pkts_tot" sub forma de sir de caractere */
		traffic.fwd_pkts_tot[j - i] = traffic_curent[j];
		j++;
	}

	// daca pachetele forward sunt mai multe de 35
	if (atoi(traffic.fwd_pkts_tot) > 35)
		result = 1;

	i = 0;
	k_virgule = 0;

	/* se copiaza valoarea de pe coloana "response_port" in
	traffic.response_port */

	/* se aloca memorie pentru detaliile de pe coloana response_port
	a capturii de trafic citite */
	traffic.response_port = calloc(MAX_CHARS_DETAILS, sizeof(char));

	/* in k_virgule se afla numarul de virgule citite
	pana la "response_port" */
	while (k_virgule <= 2) {
		if (traffic_curent[i] == ',')
			k_virgule++;
		i++;
	}

	// lui j i se atribuie pozitia primului caracter din coloana analizata
	j = i;

	while (traffic_curent[j] != ',') {
		/* in "traffic.response_port" se pastreaza valoarea
		de pe coloana "response_port" sub forma de sir de caractere */
		traffic.response_port[j - i] = traffic_curent[j];
		j++;
	}

	// daca response port este 1947 sau 138
	if (atoi(traffic.response_port) == 1947)
		result = 1;
	if (atoi(traffic.response_port) == 138)
		result = 1;
}

int main(void)
{
	// pentru citire si scriere din/in fisier
	FILE *fout = fopen("urls-predictions.out", "w"),
	*fin = fopen("data/urls/urls.in", "r");
	// primeste prima linie din fisier
	url_size = getline(&url_curent, &buf_size, fin);
	// citire din fisierul "urls.in" a fiecarui URL si procesarea acestuia
	while (url_size >= 0) {
		task1_part1();
		if (result == 1) {
			fprintf(fout, "1\n");
		/* daca NU a fost gasit un domeniu care coincide cu host-ul URL-ului */
		} else {
			task1_part2();
			if (result == 1)
				fprintf(fout, "1\n");
			else
				fprintf(fout, "0\n");
		}
		// se elibereaza memoria alocata dinamic
		free(url.host);
		free(url.path);
		free(url_curent);
		/* se aloca memorie pentru 500 de caractere
		fiindca nu se stie cate caractere are urmatorul URL din urls.in */
		url_curent = calloc(MAX_CHARS, sizeof(char));
		// se citeste urmatorul URL din "urls.in"
		url_size = getline(&url_curent, &buf_size, fin);
	}
	// eliberare memorie din "url_curent"
	free(url_curent);
	// inchiderea fisierelor
	fclose(fin);
	fclose(fout);
	// pentru citire si scriere din/in fisier
	FILE *tout = fopen("traffic-predictions.out", "w"),
	*tin = fopen("data/traffic/traffic.in", "r");
	traffic_curent = calloc(MAX_CHARS, sizeof(char));
	// primeste prima linie din fisier
	line_size = getline(&traffic_curent, &buf_size, tin);
	result = 0;
	/* daca se citeste prima linie, first_line primeste valoarea 1,
	daca nu, first_line primeste valoarea 0 */
	unsigned int first_line = 1;
	// citire din "traffic.in" a fiecarei intrari si procesarea acesteia
	while (line_size >= 0) {
		result = 0;
		if (first_line != 1) {
			task2_part1();
			task2_part2();
			if (result == 1)
				fprintf(tout, "1\n");
			else
				fprintf(tout, "0\n");
			// se elibereaza memoria alocata dinamic
			free(traffic.flow_duration);
			free(traffic.flow_pkts_payload);
			free(traffic.fwd_pkts_tot);
			free(traffic.response_port);
			free(traffic_curent);
			/* se aloca memorie pentru 500 de caractere fiindca nu se stie
			cate caractere are urmatoarea intrare din traffic.in */
			traffic_curent = calloc(MAX_CHARS, sizeof(char));
			// se citeste urmatorul URL din "urls.in"
			line_size = getline(&traffic_curent, &buf_size, tin);
			// daca se citeste prima linie din fisier (antetul)
			if (first_line == 1)
				first_line = 0;
		} else {
			// se citeste urmatorul URL din "urls.in"
			line_size = getline(&traffic_curent, &buf_size, tin);
			first_line = 0;
		}
	}
	// eliberare memorie din "traffic_curent"
	free(traffic_curent);
	// inchiderea fisierelor
	fclose(tin);
	fclose(tout);
}
