/* vim: set noet sts=8 ts=8 sw=8 tw=78: */
#define SPDY_USE_DMEM
#include <spdy.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <sys/select.h>

static int tx_wait;

static void send_wait(void* u) {
	(void) u;
	tx_wait = 1;
}

int main(void) {
	SSL_CTX *ctx;
	int fd;
	spdy_connection* c;
	spdy_stream* s;
	spdy_request r;
	fd_set read, write;

	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	ctx = SSL_CTX_new(SSLv23_client_method());

	c = spdyC_connect("www.foobar.co.nz:443", ctx, &fd);

	memset(&r, 0, sizeof(r));
	r.host = C("www.foobar.co.nz");
	r.path = C("/bind?hostname=aeir");

	s = spdyS_new();
	spdyS_ref(s);
	spdyC_start(c, s, &r);

	for (;;) {
		FD_ZERO(&read);
		FD_ZERO(&write);
		FD_SET(fd, &read);

		if (tx_wait) {
			FD_SET(fd, &write);
		}

		select(fd+1, &read, &write, NULL, NULL);
		tx_wait = 0;

		if (FD_ISSET(fd, &read)) {
			spdyC_recv_ready(c);
		}

		if (FD_ISSET(fd, &write)) {
			spdyC_send_ready(c);
		}
	}

	return 0;
}

