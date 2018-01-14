#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#include <string.h>
#include <openssl/ssl.h>

/*
 * DNSSEC Authentication Chain TLS extension type value
 */

#define DNSSEC_CHAIN_EXT_TYPE 53

/*
 * Linked List of Wire format RRs and associated routines.
 */

typedef struct wirerr {
    getdns_bindata *node;
    struct wirerr *next;
} wirerr;

wirerr *wirerr_list = NULL;
size_t wirerr_count = 0;
size_t wirerr_size = 0;

wirerr *insert_wirerr(wirerr *current, getdns_bindata *new)
{
    wirerr *w = malloc(sizeof(wirerr));
    w->node = new;
    w->next = NULL;
    wirerr_count++;
    wirerr_size += new->size;

    if (current == NULL) {
        wirerr_list = w;
    } else
        current->next = w;
    return w;
}

void free_wirerr_list(wirerr *head)
{
    wirerr *current;
    while ((current = head) != NULL) {
        head = head->next;
        free(current->node->data);
        free(current->node);
        free(current);
    }
    return;
}

getdns_bindata *getchain(char *qname, uint16_t qtype) {
    unsigned char *cp;
    uint32_t status;
    getdns_context *ctx = NULL;
    getdns_return_t rc;
    getdns_dict    *extensions = NULL;
    getdns_dict *response;
    getdns_bindata *chaindata = malloc(sizeof(getdns_bindata));
    wirerr *wp = wirerr_list;

    rc = getdns_context_create(&ctx, 1);
    if (rc != GETDNS_RETURN_GOOD) {
        (void) fprintf(stderr, "Context creation failed: %d", rc);
        return NULL;
    }

    if (! (extensions = getdns_dict_create())) {
        fprintf(stderr, "FAIL: Error creating extensions dict\n");
        return NULL;
    }

    if ((rc = getdns_dict_set_int(extensions, "dnssec_return_only_secure",
                                  GETDNS_EXTENSION_TRUE))) {
        fprintf(stderr, "FAIL: setting dnssec_return_only_secure: %s\n",
                getdns_get_errorstr_by_id(rc));
        return NULL;
    }

    if ((rc = getdns_dict_set_int(extensions, "dnssec_return_validation_chain",
                                  GETDNS_EXTENSION_TRUE))) {
        fprintf(stderr, "FAIL: setting +dnssec_return_validation_chain: %s\n",
                getdns_get_errorstr_by_id(rc));
        return NULL;
    }

    rc = getdns_general_sync(ctx, qname, qtype, extensions, &response);
    if (rc != GETDNS_RETURN_GOOD) {
        (void) fprintf(stderr, "getdns_general() failed, rc=%d, %s\n",
                       rc, getdns_get_errorstr_by_id(rc));
        getdns_context_destroy(ctx);
        return NULL;
    }

    (void) getdns_dict_get_int(response, "status", &status);

    switch (status) {
    case GETDNS_RESPSTATUS_GOOD:
        break;
    case GETDNS_RESPSTATUS_NO_NAME:
        fprintf(stderr, "FAIL: %s: Non existent domain name.\n", qname);
        return NULL;
    case GETDNS_RESPSTATUS_ALL_TIMEOUT:
        fprintf(stderr, "FAIL: %s: Query timed out.\n", qname);
        return NULL;
    case GETDNS_RESPSTATUS_NO_SECURE_ANSWERS:
        fprintf(stderr, "%s: Insecure address records.\n", qname);
        return NULL;
    case GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS:
        fprintf(stderr, "FAIL: %s: All bogus answers.\n", qname);
        return NULL;
    default:
        fprintf(stderr, "FAIL: %s: error status code: %d.\n", qname, status);
        return NULL;
    }

    getdns_list *replies_tree;
    rc = getdns_dict_get_list(response, "replies_tree", &replies_tree);
    if (rc != GETDNS_RETURN_GOOD) {
        (void) fprintf(stdout, "dict_get_list: replies_tree: rc=%d\n", rc);
        return NULL;
    }

    size_t reply_count;
    (void) getdns_list_get_length(replies_tree, &reply_count);

    size_t i;
    for ( i = 0; i < reply_count; i++ ) {

        getdns_dict *reply;
        getdns_list *answer;
        size_t rr_count;
        size_t j;

        (void) getdns_list_get_dict(replies_tree, i, &reply);
        (void) getdns_dict_get_list(reply, "answer", &answer);
        (void) getdns_list_get_length(answer, &rr_count);

        if (rr_count == 0) {
            (void) fprintf(stderr, "FAIL: %s: NODATA response.\n", qname);
            return NULL;
        }

        for ( j = 0; j < rr_count; j++ ) {
            getdns_dict *rr = NULL;
            getdns_bindata *wire = malloc(sizeof(getdns_bindata));
            (void) getdns_list_get_dict(answer, j, &rr);
            rc = getdns_rr_dict2wire(rr, &wire->data, &wire->size);
            if (rc != GETDNS_RETURN_GOOD) {
                (void) fprintf(stderr, "rrdict2wire() failed: %d\n", rc);
                return NULL;
            }
            wp = insert_wirerr(wp, wire);
        }

    }

    getdns_list *val_chain;
    rc = getdns_dict_get_list(response, "validation_chain", &val_chain);
    if (rc != GETDNS_RETURN_GOOD) {
        (void) fprintf(stderr, "FAIL: getting validation_chain: rc=%d\n", rc);
        return NULL;
    }

    size_t rr_count;
    (void) getdns_list_get_length(val_chain, &rr_count);

    for ( i = 0; i < rr_count; i++ ) {
        getdns_dict *rr = NULL;
        getdns_bindata *wire = malloc(sizeof(getdns_bindata));
        (void) getdns_list_get_dict(val_chain, i, &rr);
        rc = getdns_rr_dict2wire(rr, &wire->data, &wire->size);
        if (rc != GETDNS_RETURN_GOOD) {
            (void) fprintf(stderr, "rrdict2wire() failed: %d\n", rc);
            return NULL;
        }
        wp = insert_wirerr(wp, wire);
    }

    getdns_context_destroy(ctx);

    /* 
     * Generate dnssec_chain extension data and return pointer to it.
     */
    chaindata->size = 4 + wirerr_size;
    chaindata->data = malloc(chaindata->size);

    cp = chaindata->data;
    *(cp + 0) = (DNSSEC_CHAIN_EXT_TYPE >> 8) & 0xff; /* Extension Type 53 */
    *(cp + 1) = (DNSSEC_CHAIN_EXT_TYPE) & 0xff;
    *(cp + 2) = (wirerr_size >> 8) & 0xff;           /* Extension (data) Size */
    *(cp + 3) = (wirerr_size) & 0xff;

    cp = chaindata->data + 4;

    for (wp = wirerr_list; wp != NULL; wp = wp->next) {
        getdns_bindata *g = wp->node;
        (void) memcpy(cp, g->data, g->size);
        cp += g->size;
    }

    return chaindata;
}

/*
 * exportierte Funktion
 */
int SSL_CTX_add_dnssec_chain_extension(SSL_CTX *ctx, char* server_name, int server_port) {

  char tlsa_name[512];
  getdns_bindata *chaindata = NULL;

  snprintf(tlsa_name, 512, "_%d._tcp.%s", server_port, server_name);

  if ((chaindata = getchain(tlsa_name, GETDNS_RRTYPE_TLSA)) != NULL) {;
      fprintf(stdout, "Got DNSSEC chain data for %s, size=%zu octets\n",
                tlsa_name, chaindata->size - 4);
  } else {
      fprintf(stderr, "Failed to get DNSSEC chain data for %s\n", tlsa_name);
      return -1;
  }

  if (!SSL_CTX_use_serverinfo(ctx, chaindata->data, chaindata->size)) {
      fprintf(stderr, "failed loading dnssec_chain_data extension.\n");
      return -2;
  }

  return 0;
}
