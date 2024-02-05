#ifdef USER_MODE

#include <string.h>

#define container_of(ptr, type, member) \
        ((type *)( \
        (char*)(ptr) - \
        (unsigned long)(&((type *)0)->member)))

#include <linux/list.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <linux/drbd_limits.h>
#include "drbd_url.h"

#define printk printf
#define kmalloc(size, unused, unused2) malloc(size)
#define kfree(p) free(p)

#else		/* windows kernel */

#include <drbd_windows.h>
#include <linux/list.h>
#include <linux/drbd_limits.h>
#include "drbd_url.h"

#endif

/* ------------------------------------------------------------------------- */

enum token {
	TK_INVALID,
	TK_RESOURCE,
	TK_PROTOCOL,
	TK_NODE,
	TK_USE_RLE,
	TK_VERIFY_ALG,
	TK_TIMEOUT,
	TK_PING_TIMEOUT,
	TK_PING_INT,
	TK_CONNECT_INT,
	TK_C_MAX_RATE,
	TK_C_FILL_TARGET,
	TK_ADDRESS,
	TK_HOSTNAME,
	TK_VOLUME,
	TK_MINOR,
	TK_DISK,
	TK_META_DISK,
	TK_SYSLOG_IP,
	TK_THIS_NODE_ID,
	TK_END,	/* insert before this token */
	TK_MAX
};

static char *token_strings[TK_MAX] = {
	"",
	"resource=",
	"protocol=",
	"node",
	"use-rle=",
	"verify-alg=",
	"timeout=",
	"ping-timeout=",
	"ping-int=",
	"connect-int=",
	"c-max-rate=",
	"c-fill-target=",
	"address=",
	"hostname=",
	"volume",
	"minor=",
	"disk=",
	"meta-disk=",
	"syslog-ip=",
	"this-node-id="
};

static char *short_token_strings[TK_MAX] = {
	"",
	"r=",
	"pr=",
	"n",
	"ur=",
	"va=",
	"t=",
	"pt=",
	"pi=",
	"ci=",
	"cmr=",
	"cft=",
	"a=",
	"h=",
	"v",
	"m=",
	"d=",
	"md=",
	"si=",
	"tn="
};

bool token_has_index(enum token t)
{
	return (t == TK_NODE || t == TK_VOLUME);
}

/* We use (for now) a semicolon, since the colon is also used for
 * IPv6 addresses (and for the port number).
 */

#define DRBD_CONFIG_SEPERATOR ';'

/* This function intentionally does not allow for leading spaces. */

static unsigned long my_strtoul(const char *nptr, const char ** endptr, int base)
{
	unsigned long val = 0;

	while (isdigit(*nptr)) {
		val *= 10;
		val += (*nptr)-'0';
		nptr++;
	}
	if (endptr)
		*endptr = nptr;

	return val;
}

static char *my_strndup(const char *s, size_t n)
{
	char *new_string;

	new_string = kmalloc(n+1, GFP_KERNEL, 'DRBD');
	if (new_string == NULL)
		return NULL;

	strncpy(new_string, s, n);
	new_string[n] = '\0';

	return new_string;
}



static enum token find_token(const char *s, int *index, const char **params_from, const char **params_to)
{
	enum token t;
	const char *to;

	if (*s == '\0')
		return TK_END;

	for (t=TK_INVALID+1;t<TK_END;t++) {
		size_t tlen = strlen(token_strings[t]);
		size_t slen = strlen(short_token_strings[t]);
		size_t len;
		int match = 0;

		if (tlen == 0 || slen == 0) continue;

			/* short version might be a substring of the long
			 * version. return length of long version instead
			 * of short version.
			 */
		len = 0;
		if (strncmp(short_token_strings[t], s, slen) == 0) {
			match = 1;
			len = slen;
		}
		if (strncmp(token_strings[t], s, tlen) == 0) {
			match = 1;
			len = tlen;
		}
		if (match) {
			if (token_has_index(t)) {
				*index = my_strtoul(s+len, params_from, 10);
			} else {
				*params_from= s+len;
			}

			to = strchr(*params_from, DRBD_CONFIG_SEPERATOR);
			if (to == NULL)
				to = strchr(*params_from, '\0');

			*params_to = to;	
			return t;
		}
	}
	return TK_INVALID;
}

static void init_params(struct drbd_params *p)
{
	if (p == NULL)
		return;

	p->net.use_rle = false;
	p->net.verify_alg = NULL;
	p->net.timeout = DRBD_TIMEOUT_DEF;
	p->net.ping_timeout = DRBD_PING_TIMEO_DEF;
	p->net.ping_int = DRBD_PING_INT_DEF;
	p->net.connect_int = DRBD_CONNECT_INT_DEF;

	p->disk.c_max_rate = DRBD_C_MAX_RATE_DEF;
	p->disk.c_fill_target = DRBD_C_FILL_TARGET_DEF;

	p->resource = NULL;
	p->protocol = -1;
	p->volume_id = -1;
	p->syslog_ip = NULL;
	p->this_node_id = -1;

	INIT_LIST_HEAD(&p->node_list);
}

/* resource=<name>;protocol=<A,B or C>; ... */

#define parse_error(s) do {\
				printk("%s", s); \
				return -EINVAL; \
			} while (0);

#define parse_error_with_context(s) do {\
				printk("near %s :\n", from); \
				printk("%s", s); \
				return -EINVAL; \
			} while (0);

static struct node *lookup_node(struct drbd_params *p, int node_id)
{
	struct node *n;

	list_for_each_entry(struct node, n, &p->node_list, list) {
		if (n->node_id == node_id)
			return n;
	}
	return NULL;
}

static struct node *lookup_or_create_node(struct drbd_params *p, int node_id)
{
	struct node *n;

	n = lookup_node(p, node_id);
	if (n != NULL)
		return n;

	n = kmalloc(sizeof(*n), GFP_KERNEL, 'DRBD');
	if (n == NULL)
		return NULL;

	n->hostname = NULL;
	n->node_id = node_id;
	n->address = NULL;

	n->volume.minor = -1;
	n->volume.disk = NULL; 
	n->volume.meta_disk = NULL;

	list_add(&n->list, &p->node_list);

	return n;
}

static int check_values(struct drbd_params *params)
{
	struct node *this_node, *n;
	int max_node_id = -1;

	if (params->resource == NULL)
		parse_error("No resource given\n");

	if (params->protocol == -1)
		parse_error("No protocol given\n");

	if (params->volume_id == -1)
		parse_error("No volume configured (use nodeX.volumeY...=val)\n");
	if (params->this_node_id == -1)
		parse_error("This node ID is unknown (use this-node-id=<n>)\n");

	if (params->net.timeout < DRBD_TIMEOUT_MIN ||
	    params->net.timeout > DRBD_TIMEOUT_MAX)
		parse_error("net.timeout setting out of range\n");

	if (params->net.ping_timeout < DRBD_PING_TIMEO_MIN ||
	    params->net.ping_timeout > DRBD_PING_TIMEO_MAX)
		parse_error("net.ping-timeout setting out of range\n");

	if (params->net.ping_int < DRBD_PING_INT_MIN ||
	    params->net.ping_int > DRBD_PING_INT_MAX)
		parse_error("net.ping-int setting out of range\n");

	if (params->net.connect_int < DRBD_CONNECT_INT_MIN ||
	    params->net.connect_int > DRBD_CONNECT_INT_MAX)
		parse_error("net.connect-int setting out of range\n");

	this_node = lookup_node(params, params->this_node_id);
	if (this_node == NULL)
		parse_error("this node does not exist (need to specify some parameters with nodeN)\n");

	list_for_each_entry(struct node, n, &params->node_list, list) {
		if (n->node_id > 32)
			parse_error("node-id out of range\n");
		if (n->hostname == NULL)
			parse_error("need hostname for node\n");
		if (n->address == NULL)
			parse_error("need address for node\n");
		if (n->node_id > max_node_id)
			max_node_id = n->node_id;
	}
	if (this_node->volume.minor == -1)
		parse_error("need valid minor for local volume\n");

/* Disk and meta_disk can be NULL. In that case we are running
 * diskless (but still need a minor).
 */

	if (max_node_id == -1)
		parse_error("No nodes?\n");
	params->num_nodes = max_node_id;

	return 0;
}

int parse_drbd_url(const char *drbd_config, struct drbd_params *params)
{
	enum token t;
	const char *params_from, *params_to, *from, *end_of_number;
	size_t params_len;
	int index;

	init_params(params);

	if (strncmp(drbd_config, "drbd:", 5) != 0) {
		printk("Parse error: drbd URL must start with drbd:\n");
		return -1;
	}
	from = drbd_config+5;

	while (1) {
		t=find_token(from, &index, &params_from, &params_to);
		if (t == TK_INVALID) {
			parse_error_with_context("Invalid token\n");
		}

		if (t == TK_END)
			break;

		params_len = params_to-params_from;

		switch (t) {
		case TK_RESOURCE:
			if (params->resource != NULL)
				parse_error_with_context("Duplicate resource= parameter\n");

			params->resource = my_strndup(params_from, params_len);

			if (params->resource == NULL)
				parse_error_with_context("Cannot allocate memory for resource name\n");
			break;

		case TK_SYSLOG_IP:
			if (params->syslog_ip != NULL)
				parse_error_with_context("Duplicate syslog_ip= parameter\n");

			params->syslog_ip = my_strndup(params_from, params_len);

			if (params->syslog_ip == NULL)
				parse_error_with_context("Cannot allocate memory for syslog_ip\n");
			break;

		case TK_THIS_NODE_ID:
			if (params->this_node_id == -1) {
				params->this_node_id = my_strtoul(params_from, &end_of_number, 10);
				if (end_of_number != params_to)
					parse_error_with_context("this node id should be numeric\n");
			} else {
				parse_error_with_context("this node id is duplicate\n");
			}

			break;
			
		case TK_PROTOCOL:
		{
			char c;

			if (params->protocol != -1)
				parse_error_with_context("Duplicate protocol= parameter\n");

			c = toupper(*params_from);
			if (c < 'A' || c > 'C')
				parse_error_with_context("Protocol must be either A, B or C\n");
			params->protocol = c - 0x40;
			break;
		}
		case TK_NODE:
		{
			struct node *node;

			node = lookup_or_create_node(params, index);
			if (node == NULL)
				parse_error_with_context("Out of memory\n");

			switch (*params_from) {
			case '.':
				params_from++;
				t=find_token(params_from, &index, &params_from, &params_to);
				params_len = params_to-params_from;
				switch (t) {
				case TK_ADDRESS:
					if (node->address != NULL)
						parse_error_with_context("Duplicate address for node parameter\n");

					node->address = my_strndup(params_from, params_len);
					if (node->address == NULL)
						parse_error_with_context("Cannot allocate memory for hostname\n");

					break;

				case TK_HOSTNAME:
					if (node->hostname != NULL)
						parse_error_with_context("Duplicate node<n>.hostname=<hostname> parameter\n");

					node->hostname = my_strndup(params_from, params_len);
					if (node->hostname == NULL)
						parse_error_with_context("Cannot allocate memory for hostname\n");
					break;

				case TK_VOLUME:
					if (params->volume_id == -1)
						params->volume_id = index;
					else if (params->volume_id != index)
						parse_error_with_context("Sorry, only one volume supported for now.\n");

					if (*params_from != '.')
						parse_error_with_context("dot expected\n");

					params_from++;
					t=find_token(params_from, &index, &params_from, &params_to);
					params_len = params_to-params_from;

					switch (t) {
					case TK_MINOR:
						if (node->volume.minor == -1)
							node->volume.minor = my_strtoul(params_from, NULL, 10);
						else
							parse_error_with_context("volume minor is duplicate\n");
						break;

					case TK_DISK:
						if (node->volume.disk != NULL)
							parse_error_with_context("Duplicate volume.disk parameter\n");
						node->volume.disk = my_strndup(params_from, params_to-params_from);
						if (node->volume.disk == NULL)
							parse_error_with_context("Cannot allocate memory for volume.disk\n");
						break;

					case TK_META_DISK:
						if (node->volume.meta_disk != NULL)
							parse_error_with_context("Duplicate volume.meta-disk parameter\n");
						node->volume.meta_disk = my_strndup(params_from, params_to-params_from);
						if (node->volume.meta_disk == NULL)
							parse_error_with_context("Cannot allocate memory for volume.meta-disk\n");
						break;
					default: 
						parse_error_with_context("Token invalid for volume\n");
					}
					break;

				default: 
					parse_error_with_context("Token invalid for node\n");
				}
				break;

			case '=':
				if (params_len == 0)
					parse_error_with_context("expected hostname\n");

				params_from++;
				params_len--;
				if (node->hostname != NULL)
					parse_error_with_context("Duplicate node<n>=<hostname> parameter\n");

				node->hostname = my_strndup(params_from, params_len);
				if (node->hostname == NULL)
					parse_error_with_context("Cannot allocate memory for hostname\n");
				break;
			default:
				parse_error_with_context("expected '.' or '=' after node\n");
			}


			break;
		}
		case TK_USE_RLE:
			if (strncmp(params_from, "yes", 3) == 0)
				params->net.use_rle = true;
			if (strncmp(params_from, "no", 2) == 0)
				params->net.use_rle = false;
			break;

		case TK_VERIFY_ALG:
			if (params->net.verify_alg != NULL)
				parse_error_with_context("Duplicate verify-alg parameter\n");
			params->net.verify_alg = my_strndup(params_from, params_len);
			if (params->net.verify_alg == NULL)
				parse_error_with_context("Cannot allocate memory for hostname\n");
			break;

		case TK_TIMEOUT:
			params->net.timeout = my_strtoul(params_from, &end_of_number, 10);
			if (end_of_number != params_to)
				parse_error_with_context("timeout should be numeric\n");
			break;

		case TK_PING_TIMEOUT:
			params->net.ping_timeout = my_strtoul(params_from, &end_of_number, 10);
			if (end_of_number != params_to)
				parse_error_with_context("ping-timeout should be numeric\n");
			break;

		case TK_PING_INT:
			params->net.ping_int = my_strtoul(params_from, &end_of_number, 10);
			if (end_of_number != params_to)
				parse_error_with_context("ping-int should be numeric\n");
			break;

		case TK_CONNECT_INT:
			params->net.connect_int = my_strtoul(params_from, &end_of_number, 10);
			if (end_of_number != params_to)
				parse_error_with_context("connect-int should be numeric\n");
			break;

		case TK_C_MAX_RATE:
			params->disk.c_max_rate = my_strtoul(params_from, &end_of_number, 10);
			if (end_of_number != params_to)
				parse_error_with_context("c-max-rate should be numeric\n");
			break;

		case TK_C_FILL_TARGET:
			params->disk.c_fill_target = my_strtoul(params_from, &end_of_number, 10);
			if (end_of_number != params_to)
				parse_error_with_context("c-fill-target should be numeric\n");
			break;

		default:
			parse_error_with_context("Token invalid\n");
			break;
		}
		if (*params_to == '\0')
			break;

		from = params_to+1;
	}
	return check_values(params);
}

void free_drbd_params_contents(struct drbd_params *p)
{
	struct node *n, *n2;

	list_for_each_entry_safe(struct node, n, n2, &p->node_list, list) {
		kfree(n->hostname);
		kfree(n->address);
		kfree(n->volume.disk);
		kfree(n->volume.meta_disk);
		list_del(&n->list);
		kfree(n);
	}
	kfree(p->net.verify_alg);
	kfree(p->resource);
	kfree(p->syslog_ip);
}

#ifdef USER_MODE

int main(int argc, const char **argv)
{
	struct drbd_params p;
	struct node *n;

	if (argc != 2) {
		printf("Usage: %s <drbd-URL>\n", argv[0]);
		exit(1);
	}
	parse_drbd_url(argv[1], &p);
	
	printf("resource is %s\n", p.resource);
	printf("protocol is %d\n", p.protocol);
	list_for_each_entry(struct node, n, &p.node_list, list) {
		printf("node %d\n", n->node_id);
	}
	free_drbd_params_contents(&p);

	return 0;
}

#endif
