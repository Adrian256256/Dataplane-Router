# Router-implementation
Harea Teodor-Adrian
323CA

Protocoale de comunicatii
Tema 1
Dataplane Router

Descriere generala cod:

    Am implementat functionalitatile routerului urmand cat mai indeaproape pasii din cerinta.
Am implementat tot ce se cerea, adica am folosit cautare binara pentru un Longest Prefix Match
eficient, am implementat procesul de dirijare, am adaugat si protocolul ARP (nu folosesc tabela
statica de ARP) si in cod este regasit si protocolul ICMP. Astfel, am reusit sa obtin punctaj
la toate testele. Pentru aceasta tema, am plecat de la notiunile invatate si implementate la
laborator.

    In cod am pus un numar mare de comentarii pentru un debugging mai usor si pentru o intelegere
mai usoara a fluxului programului.

    Codul este impartit in main si cateva functii specifice cazurilor pe care trebuie sa le
trateze routerul.

    In main se fac verificarile generale specifice pachetelor. Main-ul apeleaza functiile
corespunzatoare si decide ce cazuri trebuie tratate in functie de datele din headere.

    Avem functiile:

- get_best_route_binary : functie de cautare binara care implementeaza algoritmul de Longest
Prefix Match.

- cmp : functie care compara prefixele si mastile din route table. Aceasta functie este folosita
la qsort, pentru sortarea tabelului cu scopul utilizarii cautarii binare in acesta.

- send_icmp_time_exceeded : daca TTL-ul este mai mic sau egal cu 1, aceasta functie trimite un
pachet ICMP specific expirarii quantei de timp.

- respond_to_icmp_echo : functie care trateaza cazul referitor la primirea unui mesaj ICMP echo
request. Aceasta trimite un ICMP echo reply.

- send_icmp_destination_unreachable : in momentul in care get_best_route_binary returneaza null,
stim ca nu exista un urmator hop pentru pachetul primit. Atunci, aceasta functie trateaza acest caz,
trimitand un pachet ICMP de tip destination unreachable.

- send_arp_request : functia este folosita cand avem nevoie de mac-ul urmatorului hop si acesta NU
se afla in CACHE-ul routerului. Se trimite un ARP request.

- respond_to_arp_request : functia trateaza cazul in care routerul primeste un arp request. Daca
el este destinatia acestui request, se trimite un pachet de tip ARP reply.

- process_arp_reply : routerul primese un pachet de tip ARP reply si il proceseaza. Adauga mac-ul
primit in CACHE si verifica daca are pachete in coada ce asteapta sa fie trimise mai departe.
