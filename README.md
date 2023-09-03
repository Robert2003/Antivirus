#### Copyright Damian Mihai-Robert 312CAb 2022-2023

### Pentru taskul 1 am utilizat urmatoarele euristici:
	- Am scris un algoritm care a gasit extensii malitioase, bazandu-se pe
	  setul de date primit, astfel am creat o baza de date de extensii rele.
	  Daca vreuna din acele extensii se regasea la finalul linkului, acesta
	  este malitios
	- Daca url-ul contine special words precum: verify, login, admin, security
	  atunci acesta este malitios
	- Am utilizat distanta Levenshtein, care calculeaza distanta(numarul de
  	  diferente) dintre 2 cuvinte, iar daca exista 1-2 greseli de scriere,
	  atunci cel mai probabil este un url de phishing
	- Am verificat ca linkurile sa nu contina mai mult de 4 puncte (".")
	  si 3 liniute ("-").
	- Am verificat sa nu aiba mai mult de 10% cifre in domeniu
	- Am verificat sa nu fie un link din baza de date de linkuri malitioase 
