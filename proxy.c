#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

struct chunk {
	struct chunk *next;
	size_t        size;
	uint8_t       data[];
};

struct session {
	BIO *sbio;
	int remote;
	struct chunk *to_bio;
	struct chunk *to_remote;
};

static void free_chunks(struct chunk *c)
{
	if (c) {
		free_chunks(c->next);
		free(c);
	}
}

static void do_bio_read(struct session *s)
{
	uint8_t buf[65536];
	ssize_t len = BIO_read(s->sbio, buf, sizeof(buf));
	struct chunk **chunk_p;

	if (len == 0) {
		/* close */
		free_chunks(s->to_remote);
		free_chunks(s->to_bio);
		s->to_remote = s->to_bio = NULL;
		BIO_free_all(s->sbio);
		s->sbio = NULL;
		close(s->remote);
		s->remote = -1;
		return;
	}
	if (len < 0) /* error */
		return;

	/* Append a new chunk */
	for (chunk_p = &s->to_remote; *chunk_p; chunk_p = &(*chunk_p)->next)
		; /* pass */

	*chunk_p = (struct chunk *)malloc(sizeof(struct chunk) + len);
	(*chunk_p)->next = NULL;
	(*chunk_p)->size = len;
	memcpy((*chunk_p)->data, buf, len);
}

static void do_bio_write(struct session *s)
{
	struct chunk *c = s->to_bio;
	if (!c)
		return;

	s->to_bio = c->next;
	BIO_write(s->sbio, c->data, c->size);
	free(c);
}

static void do_remote_read(struct session *s)
{
	uint8_t buf[65536];
	ssize_t len = read(s->remote, buf, sizeof(buf));
	struct chunk **chunk_p;
	SSL *ssl;
	int sock;

	if (len == 0) {
		/* close */
		free_chunks(s->to_remote);
		free_chunks(s->to_bio);
		s->to_remote = s->to_bio = NULL;
		BIO_get_ssl(s->sbio, &ssl);
		SSL_shutdown(ssl);
		BIO_get_fd(s->sbio, &sock);
		close(sock);
		BIO_free_all(s->sbio);
		s->sbio = NULL;
		s->remote = -1;
		return;
	}
	if (len < 0) /* error */ {
		perror("read()");
		return;
	}

	/* Append a new chunk */
	for (chunk_p = &s->to_bio; *chunk_p; chunk_p = &(*chunk_p)->next)
		; /* pass */

	*chunk_p = (struct chunk *)malloc(sizeof(struct chunk) + len);
	(*chunk_p)->next = NULL;
	(*chunk_p)->size = len;
	memcpy((*chunk_p)->data, buf, len);
}

static void do_remote_write(struct session *s)
{
    ssize_t count;
	struct chunk *c = s->to_remote;
	if (!c)
		return;

	s->to_remote = c->next;
	count = write(s->remote, c->data, c->size);
        (void) (count);
	free(c);
}

/*
 * exported function
 */
void do_proxy(const char *proxy, BIO *acpt)
{
	int accept_sock;
	fd_set rfds, wfds;
	struct session sessions[FD_SETSIZE];
	int i, r, sock;
	BIO *sbio;
	struct sockaddr_in sa_in;
	socklen_t sa_len = sizeof(sa_in);


	if (!strchr(proxy, ':')) {
		fprintf(stderr, "Could not read port from proxy address\n");
		exit(EXIT_FAILURE);
	}
	sa_in.sin_family = AF_INET;
	sa_in.sin_port = htons(atoi(strchr(proxy, ':')+1));
	*strchr(proxy, ':') = 0;
	if (inet_pton(AF_INET, proxy, (void *)&sa_in.sin_addr.s_addr) <= 0) {
		perror("inet_pton()");
		exit(EXIT_FAILURE);
	}

	memset(&sessions, 0, sizeof(sessions));
	BIO_get_fd(acpt, &accept_sock);
	for (;;) {
		int max_fd;

		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_SET(accept_sock, &rfds);

		max_fd = accept_sock;
		for (i = 0; i < FD_SETSIZE; i++) {
			if (!sessions[i].sbio)
				continue;
			FD_SET(i, &rfds);
			if (sessions[i].to_bio)
				FD_SET(i, &wfds);
			FD_SET(sessions[i].remote, &rfds);
			if (sessions[i].to_remote)
				FD_SET(sessions[i].remote, &wfds);
			if (i > max_fd)
				max_fd = i;
			if (sessions[i].remote > max_fd)
				max_fd = sessions[i].remote;
		}
		max_fd += 1;
		r = select(max_fd, &rfds, &wfds, NULL, NULL);
		if (r == -1)
			perror("select()");

		while (FD_ISSET(accept_sock, &rfds)) {
			if(BIO_do_accept(acpt) <= 0) {
			       fprintf(stderr, "Error in connection\n");
			       ERR_print_errors_fp(stderr);
			       break;
			}

			sbio = BIO_pop(acpt);

			if(BIO_do_handshake(sbio) <= 0) {
			       fprintf(stderr, "Error in SSL handshake\n");
			       ERR_print_errors_fp(stderr);
			       break;
			}

			BIO_get_fd(sbio, &sock);
			sessions[sock].sbio = sbio;
			sessions[sock].remote = socket(AF_INET, SOCK_STREAM, 0);
			if (connect(sessions[sock].remote,
			    (struct sockaddr*)&sa_in, sa_len) < 0) {
				perror("connect()");
			}
			break;
		}
		for (i = 0; i < FD_SETSIZE; i++) {
			if (!sessions[i].sbio)
				continue;

			if (FD_ISSET(i, &wfds)) {
				do_bio_write(&sessions[i]);
			}
			if (FD_ISSET(sessions[i].remote, &wfds)) {
				do_remote_write(&sessions[i]);
			}
			if (FD_ISSET(i, &rfds)) {
				do_bio_read(&sessions[i]);
			}
			/* otherwise we get "*** buffer overflow detected ***" */
			if (sessions[i].remote < 0)
				continue;

			if (FD_ISSET(sessions[i].remote, &rfds)) {
				do_remote_read(&sessions[i]);
			}
		}
	}
}
