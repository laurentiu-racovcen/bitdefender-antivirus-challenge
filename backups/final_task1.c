#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// numarul maxim de caractere dintr-un URL
#define MAX_CHARS 500

struct url_structure {
	char *host;
	char *path;
};

struct url_structure url;

int i;

ssize_t url_size;
char *url_curent;
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
		else
			result = 0;
	}
	/* daca host-ul contine ".ru",
	atunci este sansa mare ca URL-ul sa nu fie benign */
	if (strstr(url.host, ".ru"))
		result = 1;

    /* se verifica daca host-ul contine doar puncte si cifre */

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

int main(void)
{
	// pentru citire si scriere din/in fisier
	FILE *fout = fopen("urls-predictions.out", "w"),
	*fin = fopen("data/urls/urls.in", "r");
	// primeste prima linie din fisier
	url_size = getline(&url_curent, &buf_size, fin);
	// citire din fisierul "urls.in" a fiecarui URL si analizarea acestuia
	while (url_size >= 0) {
		task1_part1();
		if (result == 1) {
			fprintf(fout, "1\n");
		/* daca NU a fost gasit un domeniu care coincide cu host-ul URL-ului
		(result = 0) */
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
}
