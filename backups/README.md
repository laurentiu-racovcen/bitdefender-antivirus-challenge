# Task 1

> În cadrul Task-ului 1 are loc detectarea URL-urilor malițioase prin intermediul unei baze de date existente de domenii malițioase și prin observarea prezenței / absenței anumitor substring-uri în URL.

Inițial, se declară următoarele:
1. Se declara o structură ("url_structure") în care sunt declarați 2 pointeri (char *host; char *path;) cu ajutorul cărora se va aloca memorie pentru procesarea ulterioară a URL-urilor;
2. Se declară variabilele necesare funcției "getline";
3. Se declară variabila "result" în care se va afla verdictul fiecarui URL.

**FUNCȚIA "MAIN"**

1. Se definesc 2 variabile de tip FILE* (fin, fout) pentru a accesa fișierele:
- urls.in, din care se citește fiecare URL, care urmeaza a fi procesat;
- urls-predictions.out, în care se scrie verdictul pentru fiecare URL din fișierul "urls.in";
2. Cu ajutorul unei bucle "while" și funcției "getline" se citește fiecare URL din fișierul "urls.in", iar acest URL se stochează în vectorul "url_curent", care are memorie alocată dinamic pentru un URL de maxim 500 de caractere;
3. În bucla "while" se apelează funcția de tip void "task1_part1()", în care se poate modifica valoarea verdictului (în variabila "result");
4. Dacă result devine 1, această valoare se afișează în "urls-predictions.out", iar dacă nu, se apelează funcția de tip void "task1_part2()" și se verifică din nou valoarea lui "result" și se afișează;
5. Se eliberează memoria alocată dinamic;
6. Ieșind din bucla "while", programul eliberează memoria alocată dinamic în "url_curent";
7. Se închid fișierele "fin" și "fout".

**FUNCȚIA task1_part1(void)**

> În cadrul funcției task1_part1(void) are loc prima parte a detectării URL-urilor malițioase (în Host-ul URL-ului). În această parte se verifică dacă Host-ul URL-ului conține un domeniu din baza de date sau dacă Host-ul conține anumite string-uri.

Detectarea a fost efectuată cu ajutorul următorului algoritm:
1. Se aloca memorie pentru URL-ul citit (în "url.host" și "url.path");
2. În "url.host" se stochează host-ul URL-ului curent;
3. Se definește variabila de tip FILE* (fin_tests) pentru a accesa fișierul domains_database", în care se află domeniile malițioase
4. Cu ajutorul unei bucle "while" se verifică dacă host-ul URL-ului curent conține un domeniu din baza de date. Dacă conține, lui result i se atribuie valoarea 1;
5. În continuare, se verifică dacă are loc unul din următoarele:
- host-ul URL-ului curent conține substring-ul ".ru"
- host-ul contine cel putin o cifra
- host-ul conține doar puncte si cifre
- daca host-ul contine string-ul "ypa"
6. Se închide fișierul "fin_tests".

**FUNCȚIA task1_part2(void)**

> În cadrul funcției task1_part2(void) are loc a doua parte a detectării URL-urilor malițioase (în PATH a URL-ului)/ În această parte se verifică dacă calea URL-ului conține un fișier cu extensie (diferită de: ".html", ".htm", ".php"), care poate fi dăunător.

Detectarea a fost efectuată cu ajutorul următorului algoritm:
1. În "url.path" se stochează calea URL-ului curent;
2. Se declară pointerul "char *p = NULL", în care se stocheaza adresa ultimului '.' din "url.path" dacă '.' există în calea URL-ului;
5. În continuare, se verifică dacă în calea URL-ului au loc toate condițiile următoare:
- ultimele 4 caractere nu sunt "html"
- urmatoarele 5 caractere de dupa ultimul punct gasit nu sunt html?
- ultimele 3 caractere din "url.path" nu sunt htm
- urmatoarele 4 caractere de dupa ultimul punct gasit nu sunt htm?
- ultimele 3 caractere din "url.path" nu sunt php
- urmatoarele 4 caractere de dupa ultimul punct gasit nu sunt php?
daca toate conditiile au fost indeplinite: result = 1;
daca nu au fost indeplinite toate conditiile: result = 0.
