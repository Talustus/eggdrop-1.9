#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "my_socket.h"

#define DNS_IPV4	1
#define DNS_IPV6	2
#define DNS_REVERSE	3

typedef struct dns_query {
	struct dns_query *next;
	char *query;
	int id;
	int (*callback)(void *client_data, const char *query, const char *result);
	void *client_data;
} dns_query_t;

typedef struct {
	unsigned short id;
	unsigned short flags;
	unsigned short question_count;
	unsigned short answer_count;
	unsigned short ns_count;
	unsigned short ar_count;
} dns_header_t;

typedef struct {
	/* char name[]; */
	unsigned short type;
	unsigned short class;
	int ttl;
	unsigned short rdlength;
	/* char rdata[]; */
} dns_rr_t;

/* Entries from resolv.conf */
typedef struct dns_server {
	char *ip;
	int idx;
} dns_server_t;

/* Entries from hosts */
typedef struct {
	char *host, *ip;
} dns_host_t;

static int query_id = 1;
static dns_header_t _dns_header = {0};
static dns_query_t *query_head = NULL;
static dns_host_t *hosts = NULL;
static int nhosts = 0;
static dns_server_t *servers = NULL;
static int nservers = 0;
static int curserver = -1;

static char separators[] = " ,\t";

static void read_resolv(char *fname);
static void read_hosts(char *fname);

/* Read in .hosts and /etc/hosts and .resolv.conf and /etc/resolv.conf */
int dns_init()
{
	FILE *fp;
	_dns_header.flags = htons(1 << 8 | 1 << 7);
	_dns_header.question_count = htons(1);
	read_resolv("/etc/resolv.conf");
	read_resolv(".resolv.conf");
	read_hosts("/etc/hosts");
	read_hosts(".hosts");
	return(0);
}

const char *dns_next_server()
{
	static int cur_server = 0;

	if (!servers || nservers < 1) return("127.0.0.1");
	if (cur_server >= nservers) cur_server = 0;
	return(servers[cur_server].ip);
}

static void add_server(char *ip)
{
	servers = (dns_server_t *)realloc(servers, (nservers+1)*sizeof(*servers));
	servers[nservers].ip = strdup(ip);
	servers[nservers].idx = -1;
	nservers++;
}

static void add_host(char *host, char *ip)
{
	hosts = (dns_host_t *)realloc(hosts, (nhosts+1)*sizeof(*hosts));
	hosts[nhosts].host = strdup(host);
	hosts[nhosts].ip = strdup(ip);
	nhosts++;
}

static int read_thing(char *buf, char *ip)
{
	int skip, len;

	skip = strspn(buf, separators);
	buf += skip;
	len = strcspn(buf, separators);
	memcpy(ip, buf, len);
	ip[len] = 0;
	return(skip + len);
}

static void read_resolv(char *fname)
{
	FILE *fp;
	char buf[512], ip[512];

	fp = fopen(fname, "r");
	if (!fp) return;
	while (fgets(buf, sizeof(buf), fp)) {
		if (!strncasecmp(buf, "nameserver", 10)) {
			read_thing(buf+10, ip);
			if (strlen(ip)) add_server(ip);
		}
	}
	fclose(fp);
}

static void read_hosts(char *fname)
{
	FILE *fp;
	char buf[512], ip[512], host[512];
	int skip, n;

	fp = fopen(fname, "r");
	if (!fp) return;
	while (fgets(buf, sizeof(buf), fp)) {
		if (strchr(buf, '#')) continue;
		skip = read_thing(buf, ip);
		if (!strlen(ip)) continue;
		while (n = read_thing(buf+skip, host)) {
			skip += n;
			if (strlen(host)) add_host(ip, host);
		}
	}
}

static int make_header(char *buf, int id)
{
	_dns_header.id = htons(id);
	memcpy(buf, &_dns_header, 12);
	return(12);
}

static int cut_host(char *host, char *query)
{
	char *period, *orig;
	int len;

	orig = query;
	while (period = strchr(host, '.')) {
		len = period - host;
		if (len > 63) return(-1);
		*query++ = len;
		memcpy(query, host, len);
		query += len;
		host = period+1;
	}
	len = strlen(host);
	if (len) {
		*query++ = len;
		memcpy(query, host, len);
		query += len;
	}
	*query++ = 0;
	return(query-orig);
}

static int reverse_ip(char *host, char *reverse)
{
	char *period;
	int offset, len;

	printf("reversing %s\n", host);
	period = strchr(host, '.');
	if (!period) {
		len = strlen(host);
		memcpy(reverse, host, len);
		return(len);
	}
	else {
		len = period - host;
		offset = reverse_ip(host+len+1, reverse);
		reverse[offset++] = '.';
		memcpy(reverse+offset, host, len);
		reverse[offset+len] = 0;
		return(offset+len);
	}
}

int dns_make_query(char *host, int type, char **buf, int *query_len, int (*callback)(), void *client_data)
{
	char *newhost = NULL;
	int len = 0;
	int ns_type = 0;
	dns_query_t *q;

	if (type == DNS_IPV4) ns_type = 1; /* IPv4 */
	else if (type == DNS_IPV6) ns_type = 28; /* IPv6 */
	else if (type == DNS_REVERSE) {
		/* We need to transform the ip address into the proper form
		 * for reverse lookup. */
		newhost = (char *)malloc(strlen(host) + 14);
		reverse_ip(host, newhost);
		strcat(newhost, ".in-addr.arpa");
		printf("newhost: %s\n", newhost);
		host = newhost;
		ns_type = 12; /* PTR (reverse lookup) */
	}
	else return(-1);

	*buf = (char *)malloc(strlen(host) + 512);
	len = make_header(*buf, query_id);
	len += cut_host(host, *buf + len);
	(*buf)[len] = 0; len++; (*buf)[len] = ns_type; len++;
	(*buf)[len] = 0; len++; (*buf)[len] = 1; len++;
	if (newhost) free(newhost);
	*query_len = len;

	q = calloc(1, sizeof(*q));
	q->id = query_id;
	query_id++;
	q->callback = callback;
	q->client_data = client_data;
	if (query_head) q->next = query_head->next;
	query_head = q;
	return(q->id);
}

static int dns_cancel_query(int id, int issue_callback)
{
	dns_query_t *q, *prev;

	prev = NULL;
	for (q = query_head; q; q = q->next) {
		if (q->id == id) break;
		prev = q;
	}
	if (!q) return(-1);
	if (prev) prev->next = q->next;
	else query_head = q->next;

	if (issue_callback) q->callback(q->client_data, q->query, NULL);
	free(q);
	return(0);
}

static int skip_name(char *ptr, char *end)
{
	int len;
	char *start = ptr;

	while ((len = *ptr++) > 0) {
		if (len > 63) {
			ptr++;
			break;
		}
		else {
			ptr += len;
		}
	}
	return(ptr - start);
}

static void got_answer(int id, char *answer)
{
	dns_query_t *q, *prev;

	printf("got_answer for id %d: %s\n", id, answer);
	prev = NULL;
	for (q = query_head; q; q = q->next) {
		if (q->id == id) break;
		prev = q;
	}
	if (!q) return;

	if (prev) prev->next = q->next;
	else query_head = q->next;

	q->callback(q->client_data, q->query, answer);
	free(q->query);
	free(q);
}

static void parse_reply(char *response, int nbytes)
{
	dns_header_t header;
	dns_rr_t reply;
	char result[512];
	char *ptr, *end;
	int i;

	ptr = response;
	memcpy(&header, ptr, 12);
	ptr += 12;

	header.id = ntohs(header.id);
	header.question_count = ntohs(header.question_count);
	header.answer_count = ntohs(header.answer_count);

	/* Pass over the question. */
	ptr += skip_name(ptr, end);
	ptr += 4;
	/* End of question. */

	for (i = 0; i < header.answer_count; i++) {
		result[0] = 0;
		/* Read in the answer. */
		ptr += skip_name(ptr, end);
		memcpy(&reply, ptr, 10);
		reply.type = ntohs(reply.type);
		reply.rdlength = ntohs(reply.rdlength);
		ptr += 10;
		if (reply.type == 1) {
			//printf("ipv4 reply\n");
			inet_ntop(AF_INET, ptr, result, 512);
			got_answer(header.id, result);
			return;
		}
		else if (reply.type == 28) {
			//printf("ipv6 reply\n");
			inet_ntop(AF_INET6, ptr, result, 512);
			got_answer(header.id, result);
			return;
		}
		else if (reply.type == 12) {
			char *placeholder;
			int len, dot;

			//printf("reverse-lookup reply\n");
			placeholder = ptr;
			result[0] = 0;
			while ((len = *ptr++) != 0) {
				if (len > 63) {
					ptr++;
					break;
				}
				else {
					dot = ptr[len];
					ptr[len] = 0;
					strcat(result, ptr);
					strcat(result, ".");
					ptr[len] = dot;
					ptr += len;
				}
			}
			if (strlen(result)) {
				result[strlen(result)-1] = 0;
				got_answer(header.id, result);
				return;
			}
			ptr = placeholder;
		}
		ptr += reply.rdlength;
	}
	got_answer(header.id, NULL);
}

int dns_lookup(const char *host, int (*callback)())
{
}

main (int argc, char *argv[])
{
	char *query, response[512], *ptr, buf[512];
	int i, len, sock;
	struct sockaddr_in server;
	dns_header_t header;
	dns_rr_t reply;
	unsigned long addr;

	if (argc != 3) {
		printf("usage: %s <host> <type>\n", argv[0]);
		printf("  <type> can be 1 (ipv4), 2 (ipv4), or 3 (reverse lookup)\n");
		return(0);
	}

	dns_init();
	if (!nservers) return(0);
	server.sin_family = AF_INET;
	server.sin_port = htons(53);
	server.sin_addr.s_addr = inet_addr(servers[0].ip);

	len = dns_make_query(argv[1], atoi(argv[2]), &query);

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (sock < 0) {
		perror("socket");
		return(1);
	}

	connect(sock, (struct sockaddr *)&server, sizeof(server));
	write(sock, query, len);
	len = read(sock, response, 512);
	printf("parsing reply, %d bytes\n", len);
	parse_reply(response, len);
	write(sock, query, len);
	len = read(sock, response, 512);
	printf("parsing next reply, %d bytes\n", len);
	parse_reply(response, len);
	return(0);
}
