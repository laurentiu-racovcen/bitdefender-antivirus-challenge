#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHARS 500

struct url_structure {
	char protocol[10];

	char *host;  // 114 caractere maxim in database
	char subdomain[120];
	char root_domain[120];

	char *path;
	char directory[MAX_CHARS];
	char file[MAX_CHARS];

	char query_string[MAX_CHARS];

	char hash[MAX_CHARS];
};

struct url_structure url;

int main(void)
{
	// pentru citire si scriere din/in fisier
	FILE *fout = fopen("urls-predictions.out", "w"),
	*fin = fopen("data/urls/urls.in", "r");

  // de facut un pointer c in care se aloca memorie dinamic (pentru a fi
  // eficient si a nu ocupa multa memorie)
  // memoria se elibereaza din pointer dupa fiecare stocare a unui URL in acesta

  // se poate de creat un struct in care se stocheaza separat: protocol, host,
  // path, query string, fragment/hash etc.

	// coloana maxima din urls.in e 372, deci se aloca suficienta memorie pentru
	// un URL de genul
	// char url_curent[MAX_CHARS];

	ssize_t url_size = 0;
	char *url_curent = NULL;

	size_t buf_size = 0;
	// url_curent = calloc(MAX_CHARS,sizeof(char));
	// primeste prima linie din fisier
	url_size = getline(&url_curent, &buf_size, fin);

	// se aloca memorie pentru URL-ul citit

	// citire din fisierul urls.in a fiecarui URL si analizarea acestuia
	while (url_size >= 0) {
		url.host = calloc(url_size + 1, sizeof(char));
		url.path = calloc(url_size + 1, sizeof(char));
		// fprintf(fout, "url=%s", url_curent);
		int i = 0;

		/* in urmatoarea bucla "while" se analizeaza fiecarea caracter al
		URL-ului analizat pana cand se ajunge la caracterul '/' de la path
		sau ':' de la port */
		while (url_curent[i] != '/' && url_curent[i] != ':' && i < url_size) {
			// in "url.host[i]", la elementul al "i"-lea, se copiaza valoarea
			// lui c[i]
			url.host[i] = url_curent[i];
			// in "i" se pastreaza numarul de caractere a host-ului
			i++;
		}

    // introducere newline dupa fiecare URL afisat

    /* se deschide fisierul "domains_database" pentru a compara
    domeniul fiecarui URL din urls.in cu domeniile din baza de date;
    fisierul "domains_database" se deschide pentru fiecare
    URL din "urls.in" */
	FILE *fin_tests = fopen("data/urls/domains_database", "r");

    // in vectorul test_host se va stoca host-ul analizat din baza de date
	char test_host[MAX_CHARS];

    // "result" - variabila in care se stocheaza raspunsul:
    // 0 - benign, 1 - malware / phishing
	unsigned int result = 0;

    /* se citeste un domeniu din baza de date si daca acesta nu s-a gasit
    in URL-ul curent, se citeste urmatorul domeniu din baza de date */
	while ((fscanf(fin_tests, "%[^\n]%*c", test_host)) != EOF && result == 0) {
		/* daca host-ul URL-ului din url.in contine un domeniu din database
		atunci result = 1, daca nu contine: result = 0 */
		if (strstr(url.host, test_host)) {
			result = 1;
			// daca host-ul contine ".ru",
			// atunci este sansa mare ca URL-ul sa nu fie benign
		} else {
			result = 0;
		}
	}
	if (strstr(url.host, ".ru"))
		result = 1;
    // se verifica daca host-ul contine doar puncte si cifre

    // se declara un contor k_c_p in care se afla
    // numarul de cifre si puncte din host
	unsigned int k_c_p = 0;
	for (int j = 0; j < strlen(url.host) - 1; j++) {
		if (url.host[j] >= 48 && url.host[j] <= 57 || url.host[j] == '.')
			k_c_p++;
	}
	if (k_c_p == strlen(url.host) - 1)
		result = 1;

    // sau daca host-ul contine cel putin o cifra, result=1
	for (int j = 0; j < strlen(url.host) - 1; j++) {
		if (url.host[j] >= 48 && url.host[j] <= 57) {
			result = 1;
			break;
		}
	}

	if (strstr(url.host, "ypa"))
		result = 1;
    // (1st layer) daca a fost gasit un domeniu care coincide cu host-ul
    // URL-ului
	if (result == 1) {
		fprintf(fout, "1\n");
    // daca NU a fost gasit un domeniu care coincide cu host-ul URL-ului
    // (result = 0)
	} else {
		/* se gaseste fisierul din calea URL-ului curent */

		// initializare j cu numarul de caractere a host-ului din URL
		unsigned int j = i;
		// fprintf(fout, "\nlength=%zu\n", url_size);
		while (j < url_size) {
			/* se copiaza fiecare caracter din PATH-ul
			URL-ului in url.path */
			url.path[j - i] = url_curent[j];
			// in "i" se pastreaza numarul de caractere a URL-ului
			j++;
		}
		// initializare j cu 0;
		j = 0;
		// afisare PATH a URL-ului
		while (j < url_size - i) {
			// fprintf(fout, "%c", url.path[j]);
			j++;
		}

		/* in pointerul "p" se stocheaza adresa ultimului '.' din
		"url.path", scopul fiind gasirea in URL a fisierului
		cu extensie, care poate fi daunator */
		char *p = NULL;
		p = strrchr(url.path, '.');

		/* daca PATH a URL-ului contine caracterul '.' (de la extensia unui
		fisier)
		daca contine, se analizeaza ultimul '.' din URL
		*/

		if (strrchr(url.path, '.')
			/* ultimele 5 caractere din "url.path" nu sunt html */
			&&
			!(url.path[strlen(url.path) - 5] == 'h' &&
				url.path[strlen(url.path) - 4] == 't' &&
				url.path[strlen(url.path) - 3] == 'm' &&
				url.path[strlen(url.path) - 2] == 'l')
			/* urmatoarele 5 caractere de dupa primul punct gasit
			nu sunt html? */
			&&
			!(p[1] == 'h' && p[2] == 't' && p[3] == 'm' && p[4] == 'l' &&
				p[5] == '?')
			// ultimele 3 caractere din "url.path" nu sunt htm
			&&
			!(url.path[strlen(url.path) - 4] == 'h' &&
				url.path[strlen(url.path) - 3] == 't' &&
				url.path[strlen(url.path) - 2] == 'm')
			// urmatoarele 4 caractere de dupa primul punct gasit nu sunt htm?
			&& !(p[1] == 'h' && p[2] == 't' && p[3] == 'm' && p[4] == '?')
			// ultimele 3 caractere din "url.path" nu sunt php
			&&
			!(url.path[strlen(url.path) - 4] == 'p' &&
				url.path[strlen(url.path) - 3] == 'h' &&
				url.path[strlen(url.path) - 2] == 'p')
			// urmatoarele 4 caractere de dupa primul punct gasit nu sunt php?
			&& !(p[1] == 'p' && p[2] == 'h' && p[3] == 'p' && p[4] == '?')) {
			result = 1;
		} else {
			result = 0;
		}
		if (result == 1) {
			// daca a fost gasit un fisier cu extensia .exe
			fprintf(fout, "1\n");
		} else {
			/* (2nd layer) daca NU a fost gasit un fisier
			cu extensia .exe */
			fprintf(fout, "0\n");
		}
	}
    // trece la urmatorul URL

	fclose(fin_tests);
    // se elibereaza memoria alocata dinamic
	free(url.host);
	free(url.path);
	free(url_curent);

    // se aloca memorie pentru MAX_CHARS
    // fiindca nu se stie cate caractere are urmatorul URL din urls.in
	url_curent = calloc(MAX_CHARS, sizeof(char));
	url_size = getline(&url_curent, &buf_size, fin);
	}
	free(url_curent);
	// inchiderea fisierelor
	fclose(fin);
	fclose(fout);
}
