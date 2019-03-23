#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>

int get_ocsp(char *filename, unsigned char **ocsp) {

  BIO			*bio;
  OCSP_RESPONSE		*response;
  int			len = -1;
  unsigned char		*p, *buf;

  if (filename == NULL) {
    *ocsp = NULL;
    return 0;
  }

  if ((bio = BIO_new_file(filename, "r")) == NULL) {
    perror("get_ocsp: BIO_new_file failed");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if ((response = d2i_OCSP_RESPONSE_bio(bio, NULL)) == NULL) {
    perror("get_ocsp: d2i_OCSP_RESPONSE_bio failed");
    ERR_print_errors_fp(stderr);
    BIO_free(bio);
    return -2;
  }

  if ((len = i2d_OCSP_RESPONSE(response, NULL)) <= 0) {
    perror("get_ocsp: i2d_OCSP_RESPONSE #1 failed");
    ERR_print_errors_fp(stderr);
    OCSP_RESPONSE_free(response);
    BIO_free(bio);
    return -3;
  }

  if ((buf = malloc((size_t) len)) == NULL) {
    perror("get_ocsp: malloc failed");
    OCSP_RESPONSE_free(response);
    BIO_free(bio);
    return -4;
  }

  p = buf;
  if ((len = i2d_OCSP_RESPONSE(response, &p)) <= 0) {
    perror("get_ocsp: i2d_OCSP_RESPONSE #2 failed");
    ERR_print_errors_fp(stderr);
    free(buf);
    OCSP_RESPONSE_free(response);
    BIO_free(bio);
    return -5;
  }

  OCSP_RESPONSE_free(response);
  BIO_free(bio);

  fprintf(stdout, "get_ocsp: %i octets\n", len);

  *ocsp = buf;
  return len;
}
