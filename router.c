#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <string.h>

struct route_table_entry *get_best_route_binary(uint32_t ip_dest, struct route_table_entry *rtable, int rtable_len) {

	struct route_table_entry * best = NULL;
	//voi face cautare binara, pentru eficientizare
	int left = 0;
	int right = rtable_len - 1;
	while (left <= right) {

		int mid = left + (right - left) / 2;

		if (rtable[mid].prefix == (ip_dest & rtable[mid].mask)) {
			best = &rtable[mid];
			for (int i = mid - 1; rtable[i].prefix <= (ip_dest & rtable[i].mask); i--) {
				if (rtable[i].mask >= best->mask)
					best = &rtable[i];
			}
			break;
		}
		if (rtable[mid].prefix > (ip_dest & rtable[mid].mask)) {
			left = mid + 1;
		} 
		if (rtable[mid].prefix < (ip_dest & rtable[mid].mask)) {
			right = mid - 1;
		}
	}
	return best;
}

int cmp(const void *a, const void *b) {
	int first_prefix = ((struct route_table_entry *)a)->prefix;
	int second_prefix = ((struct route_table_entry *)b)->prefix;
	int first_mask = ((struct route_table_entry *)a)->mask;
	int second_mask = ((struct route_table_entry *)b)->mask;
	if (first_prefix == second_prefix) {
		return second_mask - first_mask;
	} else {
		return second_prefix - first_prefix;
	}
}

void send_icmp_time_exceeded(int interface, char *buf, size_t len) {
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	uint8_t my_mac_address[6];
	get_interface_mac(interface, my_mac_address);
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	//trimit pachet de tip icmp de tip "Time exceeded" inapoi la sursa
	//schimb mac-ul destinatie cu mac-ul sursa
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	//schimb mac-ul sursa cu mac-ul meu
	memcpy(eth_hdr->ether_shost, my_mac_address, 6);
	//salvez primii 64 de biti de dupa ip_hdr
	char *data = buf + sizeof(struct ether_header) + sizeof(struct iphdr);
	//setez protocolul pe ICMP
	ip_hdr->protocol = IPPROTO_ICMP;
	//am alta lungime la ip_hdr, o actualizez
	ip_hdr->tot_len = htons(ntohs(ip_hdr->tot_len) + sizeof(struct icmphdr));
	//creez un pachet de tip icmp de tip "Time exceeded"
	struct icmphdr icmphdr;
	icmphdr.type = 11;
	icmphdr.code = 0;
	icmphdr.checksum = 0;
	icmphdr.checksum = checksum((u_int16_t*) &icmphdr, sizeof(struct icmphdr));
	//lipesc pachetul la buffer
	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr), &icmphdr, sizeof(struct icmphdr));
	//lipesc datele la buffer
	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), data, 64);
	//actualizez length
	len = len + sizeof(struct icmphdr);
	//trimit pachetul
	send_to_link(interface, buf, len);
}

void respond_to_icmp_echo(int interface, char *buf, size_t len) {
	uint8_t my_mac_address[6];
	get_interface_mac(interface, my_mac_address);
	struct ether_header *eth_hdr = (struct ether_header *) buf;

	//verific daca am type 8 code 0
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	if (icmp_hdr->type == 8 && icmp_hdr->code == 0) {
		//trimit un pachet de tip icmp echo reply
		//schimb mac-ul destinatie cu mac-ul sursa
		memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
		//schimb mac-ul sursa cu mac-ul meu
		memcpy(eth_hdr->ether_shost, my_mac_address, 6);
		//creez un pachet de tip icmp de tip "Echo reply"
		struct icmphdr icmphdr;
		icmphdr.type = 0;
		icmphdr.code = 0;
		icmphdr.checksum = 0;
		icmphdr.checksum = checksum((u_int16_t*) &icmphdr, sizeof(struct icmphdr));
		//lipesc pachetul la buffer
		memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr), &icmphdr, sizeof(struct icmphdr));
		
		//trimit pachetul
		send_to_link(interface, buf, len);
	}
}

void send_icmp_destination_unreachable(int interface, char *buf, size_t len) {
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	uint8_t my_mac_address[6];
	get_interface_mac(interface, my_mac_address);
	struct ether_header *eth_hdr = (struct ether_header *) buf;

	//nu am gasit o ruta, trimit pachet de tip icmp de tip "Destination unreachable"
	//schimb mac-ul destinatie cu mac-ul sursa
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	//schimb mac-ul sursa cu mac-ul meu
	memcpy(eth_hdr->ether_shost, my_mac_address, 6);
	//salvez primii 64 de biti de dupa ip_hdr
	char *data = buf + sizeof(struct ether_header) + sizeof(struct iphdr);
	//setez protocolul pe ICMP
	ip_hdr->protocol = IPPROTO_ICMP;
	//am alta lungime la ip_hdr, o actualizez
	ip_hdr->tot_len = htons(ntohs(ip_hdr->tot_len) + sizeof(struct icmphdr));
	//creez un pachet de tip icmp de tip "Destination unreachable"
	struct icmphdr icmphdr;
	icmphdr.type = 3;
	icmphdr.code = 0;
	icmphdr.checksum = 0;
	icmphdr.checksum = checksum((u_int16_t*) &icmphdr, sizeof(struct icmphdr));
	//lipesc pachetul la buffer
	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr), &icmphdr, sizeof(struct icmphdr));
	//lipesc datele la buffer
	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), data, 64);
	//actualizez length
	len = len + sizeof(struct icmphdr) + 64;
	//trimit pachetul
	send_to_link(interface, buf, len);
}

void send_arp_request(int interface, struct route_table_entry *best_route, queue *q, char *buf, size_t len) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	//adaug pachetul curent in coada pentru asteptarea mac-ului
	char *packet = malloc(len);
	memcpy(packet, buf, len);
	queue_enq(*q, packet);

	//daca nu am mac-ul in cache, trimit un pachet de tip arp
	//creez un pachet de tip arp
	struct ether_header *eth_hdr_arp = (struct ether_header *) buf;
	eth_hdr_arp->ether_dhost[0] = 0xff;
	eth_hdr_arp->ether_dhost[1] = 0xff;
	eth_hdr_arp->ether_dhost[2] = 0xff;
	eth_hdr_arp->ether_dhost[3] = 0xff;
	eth_hdr_arp->ether_dhost[4] = 0xff;
	eth_hdr_arp->ether_dhost[5] = 0xff;

	get_interface_mac(best_route->interface, eth_hdr->ether_shost);
	eth_hdr_arp->ether_type = htons(0x0806);
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	get_interface_mac(best_route->interface, arp_hdr->sha);
	arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
	memset(arp_hdr->tha, 0, 6);
	arp_hdr->tpa = best_route->next_hop;
	//actualizez len
	len = sizeof(struct ether_header) + sizeof(struct arp_header);
	//trimit pachetul
	send_to_link(best_route->interface, buf, len);
}

void respond_to_arp_request(int interface, char *buf, size_t len) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
	uint8_t my_mac_address[6];
	get_interface_mac(interface, my_mac_address);
	//verific daca ip-ul destinatie este al meu
	char *my_ip = get_interface_ip(interface);
	if (arp_hdr->tpa == inet_addr(my_ip)) {
		//creez un pachet de tip arp reply
		//schimb mac-ul destinatie cu mac-ul sursa
		memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
		//schimb mac-ul sursa cu mac-ul meu
		memcpy(eth_hdr->ether_shost, my_mac_address, 6);
		//schimb op-ul
		arp_hdr->op = htons(2);
		//schimb mac-ul destinatie cu mac-ul sursa
		memcpy(arp_hdr->tha, arp_hdr->sha, 6);
		//schimb mac-ul sursa cu mac-ul meu
		memcpy(arp_hdr->sha, my_mac_address, 6);
		//schimb ip-ul destinatie cu ip-ul sursa
		uint32_t aux = arp_hdr->tpa;
		arp_hdr->tpa = arp_hdr->spa;
		arp_hdr->spa = aux;
		//trimit pachetul
		send_to_link(interface, buf, len);
	} else {
		//nu sunt destinatia corecta pentru acest arp request
	}
}

void process_arp_reply(char *buf, int len, struct arp_table_entry *cache, int *cache_len, queue *q,
						struct route_table_entry *rtable, int rtable_size, int interface) {
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
	uint8_t my_mac_address[6];
	get_interface_mac(interface, my_mac_address);
	//adaug mac-ul in cache
	cache[*cache_len].ip = arp_hdr->spa;
	memcpy(cache[*cache_len].mac, arp_hdr->sha, 6);
	*cache_len = *cache_len + 1;
	//caut in coada pachetul care asteapta mac-ul
	//am grija sa nu pierd pachetele
	//scot cate unul din coada, il verific, si daca nu este cel corect, il pun in q_aux
	queue q_aux = queue_create();
	while (!queue_empty(*q)) {
		char *packet = queue_deq(*q);
		struct ether_header *eth_hdr_aux = (struct ether_header *) packet;
		struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
		struct route_table_entry *best_route = get_best_route_binary(ip_hdr->daddr, rtable, rtable_size);
		if (best_route->next_hop == arp_hdr->spa) {
			//am gasit pachetul corect
			//scriu mac-ul in pachet
			memcpy(eth_hdr_aux->ether_dhost, arp_hdr->sha, 6);
			//schimb mac-ul sursa cu mac-ul meu
			memcpy(eth_hdr_aux->ether_shost, my_mac_address, 6);
			//recalculez checksum-ul
			struct iphdr *ip_hdr_aux = (struct iphdr *)(packet + sizeof(struct ether_header));
			ip_hdr_aux->check = 0;
			ip_hdr_aux->check = htons(checksum((u_int16_t*) ip_hdr_aux, sizeof(struct iphdr)));
			//inainte sa trimit pachetul, adaug pachetele din q_aux inapoi in coada
			while (!queue_empty(q_aux)) {
				char *packet = queue_deq(q_aux);
				queue_enq(*q, packet);
			}
			//trimit pachetul
			send_to_link(interface, packet, len);
		} else {
			//pachetul nu este cel corect, il pun in q_aux
			queue_enq(q_aux, packet);
		}
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	//citesc tabela de rutare
	struct route_table_entry *rtable = malloc(80000 * sizeof(struct route_table_entry));
	int rtable_size = read_rtable(argv[1], rtable);
	//sortez tabela de rutare
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), cmp);

	//creez un cache pentru arp
	int cache_len = 0; //adaug pe masura ce obtin mac-uri prin protocolul arp
	struct arp_table_entry *cache = malloc(80000 * sizeof(struct arp_table_entry));	

	//creez o coada pentru pachetele care asteapta mac-ul
	queue q;
	q = queue_create();
	
	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		
		//verific daca sunt destinatia corecta
		uint8_t my_mac_address[6];
		get_interface_mac(interface, my_mac_address); //mac-ul meu
		if (memcmp(eth_hdr->ether_dhost, my_mac_address, 6) != 0) {
			//verific daca adresa este de broadcast
			uint8_t broadcast_address[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
			if (memcmp(eth_hdr->ether_dhost, broadcast_address, 6) != 0) {
				//nu sunt eu destinatia corecta
				continue;
			}
		}

		//verific in ether_type, in eth_hrd, ce fel de protocol avem
		if (ntohs(eth_hdr->ether_type) == 0x0800) { //pentru ipv4
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			//verific daca adresa ip destinatie este a mea
			char *my_ip = get_interface_ip(interface);
			if (ip_hdr->daddr == inet_addr(my_ip)) {
				//eu sunt destinatia
				//daca in ip_hdr-> protocol avem icpm, atunci pot fi destinatar
				if (ip_hdr->protocol == IPPROTO_ICMP) {
					respond_to_icmp_echo(interface, buf, len);
				}
				//daca nu, arunc pachetul
				continue;
			}

			//verific daca checksum-ul este corect
			uint16_t old_checksum = ntohs(ip_hdr->check); //checksum-ul primit
			ip_hdr->check = 0;
			uint16_t new_checksum = checksum((u_int16_t*) ip_hdr, sizeof(struct iphdr));
			if (old_checksum != new_checksum) {
				//checksum-ul nu este corect, arunc pachetul
				continue;
			}
			//verific daca TLL este 1 sau 0, daca da, trimit ICPM time exceeded
			if (ip_hdr->ttl <= 1) {
				send_icmp_time_exceeded(interface, buf, len);
				continue;
			}
			//decrementez ttl-ul
			ip_hdr->ttl--;

			//caut in tabela de rutare urmatorul hop
			struct route_table_entry *best_route = get_best_route_binary(ip_hdr->daddr, rtable, rtable_size);
			if (best_route == NULL) {
				send_icmp_destination_unreachable(interface, buf, len);
				continue;
			}
			//schimb mac-ul destinatie cu mac-ul urmatorului hop
			uint8_t next_hop_mac[6];

			//ARP PROTOCOL
			//verific daca am mac-ul in cache
			int found = 0;
			for (int i = 0; i < cache_len; i++) {
				if (cache[i].ip == best_route->next_hop) {
					memcpy(next_hop_mac, cache[i].mac, 6);
					found = 1;
					break;
				}
			}
			if (found == 0) {
				send_arp_request(interface, best_route, &q, buf, len);
			} else {
				//am gasit mac-ul in cache
				memcpy(eth_hdr->ether_dhost, next_hop_mac, 6);
				//schimb mac-ul sursa cu mac-ul meu
				memcpy(eth_hdr->ether_shost, my_mac_address, 6);
				//recalculez checksum-ul
				ip_hdr->check = 0;
				ip_hdr->check = htons(checksum((u_int16_t*) ip_hdr, sizeof(struct iphdr)));
				//trimit pachetul
				send_to_link(best_route->interface, buf, len);
			}
		}

		if (ntohs(eth_hdr->ether_type) == 0x0806) { //pentru arp
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
			if (ntohs(arp_hdr->op) == 1) { //request
				respond_to_arp_request(interface, buf, len);
			} else if (ntohs(arp_hdr->op) == 2) { //reply
				process_arp_reply(buf, len, cache, &cache_len, &q, rtable, rtable_size, interface);
			}
		}
	}
}

