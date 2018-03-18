#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <pwd.h>

#include "ocsp-stapling.h"
#include "dnssec-chain-extension.h"
#include "proxy.h"

#define DEFAULT_SERVER_PORT             "443"
#define DEFAULT_SERVER_CERT_FILE	"cert+intermediate.pem"
#define DEFAULT_SERVER_KEY_FILE		"key.pem"
#define DEFAULT_OSCP_STAPLING_FILE	"ocsp.response"

char *server_name;
char *server_port			= DEFAULT_SERVER_PORT;
char *certfile				= DEFAULT_SERVER_CERT_FILE;
char *keyfile				= DEFAULT_SERVER_KEY_FILE;
char *ocspfile				= DEFAULT_OSCP_STAPLING_FILE;
char *chrootdir                         = NULL;
char *username                          = NULL;
struct passwd *pwentry                  = NULL;

char *hostname;
uint16_t portnumber;

static unsigned char *ocsp;
long ocsp_len;

char *proxy;

void print_usage(const char* progname) {

    char *hostname;

    /* may fail */
    hostname = malloc(512);
    gethostname(hostname, 512);

    fprintf(stdout, "\nUsage: %s [options]\n\n"
            "  -h                  print this help message\n"
            "  -sname  <name>      server name               default: %s\n"
            "  -port   <port>      server port               default: %s\n"
            "  -cert   <file>      server certificate file   default: ./%s\n"
            "  -key    <file>      server private key file   default: ./%s\n"
            "  -oscp   <file>      server ocsp response file default: ./%s\n"
            "  -chroot <dir>       chroot to directory       default: don't chroot\n"
            "  -user   <name>      switch to that user       default: don't switch user\n"
            "  -proxy  <ip>:<port> IPv4 address and port to forward to\n"
            "\n",
            progname,
            hostname,
            DEFAULT_SERVER_PORT,
            DEFAULT_SERVER_CERT_FILE,
            DEFAULT_SERVER_KEY_FILE,
            DEFAULT_OSCP_STAPLING_FILE
    );
    exit(1);
}

void parse_options(const char *progname, int argc, char **argv) {

    int		i;

    for (i = 1; i < argc; i++) {

        char	*optword;
        optword = argv[i];

        if (!strcmp(optword, "-h")) {
            print_usage(progname);
        } else if (!strcmp(optword, "-sname")) {
            if (++i >= argc || !*argv[i]) {
                fprintf(stderr, "-sname: server name.\n");
                print_usage(progname);
            }
            server_name = argv[i];
        } else if (!strcmp(optword, "-port")) {
            if (++i >= argc || !*argv[i]) {
                fprintf(stderr, "-port: server port.\n");
                print_usage(progname);
            }
            server_port = argv[i];
        } else if (!strcmp(optword, "-cert")) {
            if (++i >= argc || !*argv[i]) {
                fprintf(stderr, "-cert: certificate file expected.\n");
                print_usage(progname);
            }
            certfile = argv[i];
        } else if (!strcmp(optword, "-key")) {
            if (++i >= argc || !*argv[i]) {
                fprintf(stderr, "-key: private key file expected.\n");
                print_usage(progname);
            }
            keyfile = argv[i];
        } else if (!strcmp(optword, "-ocsp")) {
            if (++i >= argc || !*argv[i]) {
                fprintf(stderr, "-oscp: ocsp response file expected.\n");
                print_usage(progname);
            }
            ocspfile = argv[i];
        } else if (!strcmp(optword, "-chroot")) {
            if (++i >= argc || !*argv[i]) {
                fprintf(stderr, "-chroot: directory expected.\n");
                print_usage(progname);
            }
            chrootdir = argv[i];
        } else if (!strcmp(optword, "-user")) {
            if (++i >= argc || !*argv[i]) {
                fprintf(stderr, "-user: username expected.\n");
                print_usage(progname);
            }
            username = argv[i];
            if ((pwentry = getpwnam(username)) == NULL) {
                fprintf(stderr, "Error: no password file entry for %s\n", username);
                print_usage(progname);
            }
        } else if (!strcmp(optword, "-proxy")) {
            if (++i >= argc || !*argv[i]) {
                fprintf(stderr, "-proxy: proxy address and port expected.\n");
                print_usage(progname);
            }
            proxy = argv[i];
        } else if (optword[0] == '-') {
            fprintf(stderr, "Unrecognized option: %s\n", optword);
            print_usage(progname);
        } else {
            break;
        }
    }

    if (certfile == NULL) {
        fprintf(stderr, "Error: no port number specified.\n");
        print_usage(progname);
    } else if ((argc - i) != 0) {
        fprintf(stderr, "Error: too many arguments.\n");
        print_usage(progname);
    }

    if (!server_name) {
        server_name = malloc(512);
        gethostname(server_name, 512);
    }

    portnumber = atoi(server_port);

    if (access(certfile, R_OK)) {
        fprintf(stderr, "Error: can't access certificate file\n");
        print_usage(progname);
    }
    if (access(keyfile, R_OK)) {
        fprintf(stderr, "Error: can't access private key file\n");
        print_usage(progname);
    }
    if (access(ocspfile, R_OK)) {
        fprintf(stdout, "can't access ocsp response file, continue without OCSP stapling.\n");
        ocspfile = NULL;
    }
}

/*
int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
    }

    return s;
}
*/

void init_openssl()
{ 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

static int add_ocsp_data_cb(SSL *s, void *arg __attribute__((unused))) {

    if (ocsp) {

        unsigned char *p;
        
        if ((p=malloc(ocsp_len)) == NULL) {
            perror("add_ocsp_data_cb: malloc");
            return SSL_TLSEXT_ERR_NOACK;
        }

        memcpy(p, ocsp, ocsp_len);
        if ((SSL_set_tlsext_status_ocsp_resp(s, p, ocsp_len)) != 1) {
            ERR_print_errors_fp(stderr);
            return SSL_TLSEXT_ERR_NOACK;
        }
       
        return SSL_TLSEXT_ERR_OK;
    } else
        return SSL_TLSEXT_ERR_NOACK;
}

void configure_context(SSL_CTX *ctx, const char *progname)
{

    /* Set the key and cert+chain */
    if (SSL_CTX_use_certificate_chain_file(ctx, certfile) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    /* hardening */
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384");
    SSL_CTX_set1_curves_list(ctx, "secp384r1:X25519");

    /* Setup session resumption capability */
    SSL_CTX_set_session_id_context(ctx, (const unsigned char*) progname, strlen(progname));

    /* enable OCSP stapling */
    SSL_CTX_set_tlsext_status_cb(ctx, add_ocsp_data_cb);
}

static volatile int done = 0;

void interrupt(int sig) {

    (void)(sig);	/* sig is unused, avoid warning */

    done = 1;
}

void sigsetup(void) {

    struct sigaction sa;

    sa.sa_flags = SA_RESETHAND;
    sa.sa_handler = interrupt;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
}

void try_chroot(void) {

    if (NULL == chrootdir)
	return;

    if (0 != chdir(chrootdir)) {
        perror("try_chroot: cannot chdir");
        exit(EXIT_FAILURE);
    }
    if (0 != chroot(chrootdir)) {
        perror("try_chroot: cannot chroot");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "chdir+chroot %s\n", chrootdir);
    chrootdir = NULL;
}

void try_setuid(void) {

    if (NULL == username)
        return;

    if (setuid(pwentry->pw_uid) != 0) {
        perror("try_setuid: cannot setuid");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "setuid(%s)\n", username);
    username = NULL;
}

int main(int argc, char **argv)
{
    const char	*progname;
    char	*host_port;
    SSL_CTX	*ctx;
    BIO		*server_bio;
    BIO         *in  = NULL;
    BIO         *tmp;
    SSL         *ssl = NULL;
    const char  reply[] = "HTTP/1.1 200 OK\nServer: openssl-demo-server\nstrict-transport-security: max-age=17777777\n\ntest\n";

    if ((progname = strrchr(argv[0], '/')))
        progname++;
    else
        progname = argv[0];

    parse_options(progname, argc, argv);

    init_openssl();

    ctx = create_context();
    configure_context(ctx, progname);

    if ((ocsp_len = get_ocsp(ocspfile, &ocsp)) < 0) {
        perror("main: get_ocsp failed");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_add_dnssec_chain_extension(ctx, server_name, portnumber) != 0 ) {
        perror("main: SSL_CTX_add_dnssec_chain failed");
        exit(EXIT_FAILURE);
    }

    server_bio = BIO_new_ssl(ctx, 0);
    BIO_get_ssl(server_bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    if ((host_port = malloc( strlen(server_name) + 1 + strlen(server_port) )) == NULL) {
        perror("main: malloc() failed");
        exit(EXIT_FAILURE);
    }
    strcpy(host_port, server_name);
    strcat(host_port, ":");
    strcat(host_port, server_port);
    fprintf(stdout, "host_port: %s\n", host_port);

    if ((in = BIO_new_accept(host_port)) == NULL) {
        ERR_print_errors_fp(stderr);
        free(host_port);
        exit(EXIT_FAILURE);
    }

    BIO_set_accept_bios(in, server_bio);

    sigsetup();

again:

    if (BIO_do_accept(in) <= 0) {
        fprintf(stderr, "Error setting up accept BIO\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    try_chroot();
    try_setuid();

    if (proxy)
        do_proxy(proxy, in);

    else while (!done) {

        BIO_write(in, reply, strlen(reply));

        tmp = BIO_pop(in);
        BIO_free_all(tmp);
        goto again;
    }

    /* Handle connections */
/*
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        const char reply[] = "HTTP/1.1 200 OK\nServer: openssl-demo-server\nstrict-transport-security: max-age=17777777\n\ntest\n";

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        else {
            SSL_write(ssl, reply, strlen(reply));

 */         /*
             * that's missing in the "Simple_TLS_Server" from https://wiki.openssl.org/
             * and make session resumption don't work out of the box
             */ /*
            SSL_shutdown(ssl);
        }

        SSL_free(ssl);
        close(client);
    }

    close(sock);
 */
    SSL_CTX_free(ctx);
    cleanup_openssl();
    free(ocsp);
}
