/* vim: set noet sts=8 ts=8 sw=8 tw=78: */
#define SPDY_USE_DMEM

#ifdef _WIN32
#include <WinSock2.h>
#else
#include <sys/select.h>
#endif

#include <spdy.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

static int tx_wait;

static void send_wait(void* u, int enabled) {
	(void) u;
	tx_wait = enabled;
}

static void SSL_MsgCallback(int write_p, int version, int content_type, const void* buf, size_t len, SSL* ssl, void* arg)
{
	const char *str_version, *str_content_type = "", *str_details1 = "", *str_details2= "";
    d_Vector(char) out = DV_INIT;

	switch (version)
    {
        case SSL2_VERSION:
            str_version = "SSL 2.0";
            break;
        case SSL3_VERSION:
            str_version = "SSL 3.0";
            break;
        case TLS1_VERSION:
            str_version = "TLS 1.0";
            break;
        case DTLS1_VERSION:
            str_version = "DTLS 1.0";
            break;
        case DTLS1_BAD_VER:
            str_version = "DTLS 1.0 (bad)";
            break;
        default:
            str_version = "???";
    }

    if (version == SSL2_VERSION)
    {
        str_details1 = "???";

        if (len > 0)
        {
            switch (((const unsigned char*)buf)[0])
            {
                case 0:
                    str_details1 = ", ERROR:";
                    str_details2 = " ???";
                    if (len >= 3)
                    {
                        unsigned err = (((const unsigned char*)buf)[1]<<8) + ((const unsigned char*)buf)[2];

                        switch (err)
                        {
                            case 0x0001:
                                str_details2 = " NO-CIPHER-ERROR";
                                break;
                            case 0x0002:
                                str_details2 = " NO-CERTIFICATE-ERROR";
                                break;
                            case 0x0004:
                                str_details2 = " BAD-CERTIFICATE-ERROR";
                                break;
                            case 0x0006:
                                str_details2 = " UNSUPPORTED-CERTIFICATE-TYPE-ERROR";
                                break;
                        }
                    }

                    break;
                case 1:
                    str_details1 = ", CLIENT-HELLO";
                    break;
                case 2:
                    str_details1 = ", CLIENT-MASTER-KEY";
                    break;
                case 3:
                    str_details1 = ", CLIENT-FINISHED";
                    break;
                case 4:
                    str_details1 = ", SERVER-HELLO";
                    break;
                case 5:
                    str_details1 = ", SERVER-VERIFY";
                    break;
                case 6:
                    str_details1 = ", SERVER-FINISHED";
                    break;
                case 7:
                    str_details1 = ", REQUEST-CERTIFICATE";
                    break;
                case 8:
                    str_details1 = ", CLIENT-CERTIFICATE";
                    break;
            }
        }
    }

    if (version == SSL3_VERSION ||
            version == TLS1_VERSION ||
            version == DTLS1_VERSION ||
            version == DTLS1_BAD_VER)
    {
        switch (content_type)
        {
            case 20:
                str_content_type = "ChangeCipherSpec";
                break;
            case 21:
                str_content_type = "Alert";
                break;
            case 22:
                str_content_type = "Handshake";
                break;
        }

        if (content_type == 21) /* Alert */
        {
            str_details1 = ", ???";

            if (len == 2)
            {
                switch (((const unsigned char*)buf)[0])
                {
                    case 1:
                        str_details1 = ", warning";
                        break;
                    case 2:
                        str_details1 = ", fatal";
                        break;
                }

                str_details2 = " ???";
                switch (((const unsigned char*)buf)[1])
                {
                    case 0:
                        str_details2 = " close_notify";
                        break;
                    case 10:
                        str_details2 = " unexpected_message";
                        break;
                    case 20:
                        str_details2 = " bad_record_mac";
                        break;
                    case 21:
                        str_details2 = " decryption_failed";
                        break;
                    case 22:
                        str_details2 = " record_overflow";
                        break;
                    case 30:
                        str_details2 = " decompression_failure";
                        break;
                    case 40:
                        str_details2 = " handshake_failure";
                        break;
                    case 42:
                        str_details2 = " bad_certificate";
                        break;
                    case 43:
                        str_details2 = " unsupported_certificate";
                        break;
                    case 44:
                        str_details2 = " certificate_revoked";
                        break;
                    case 45:
                        str_details2 = " certificate_expired";
                        break;
                    case 46:
                        str_details2 = " certificate_unknown";
                        break;
                    case 47:
                        str_details2 = " illegal_parameter";
                        break;
                    case 48:
                        str_details2 = " unknown_ca";
                        break;
                    case 49:
                        str_details2 = " access_denied";
                        break;
                    case 50:
                        str_details2 = " decode_error";
                        break;
                    case 51:
                        str_details2 = " decrypt_error";
                        break;
                    case 60:
                        str_details2 = " export_restriction";
                        break;
                    case 70:
                        str_details2 = " protocol_version";
                        break;
                    case 71:
                        str_details2 = " insufficient_security";
                        break;
                    case 80:
                        str_details2 = " internal_error";
                        break;
                    case 90:
                        str_details2 = " user_canceled";
                        break;
                    case 100:
                        str_details2 = " no_renegotiation";
                        break;
                    case 110:
                        str_details2 = " unsupported_extension";
                        break;
                    case 111:
                        str_details2 = " certificate_unobtainable";
                        break;
                    case 112:
                        str_details2 = " unrecognized_name";
                        break;
                    case 113:
                        str_details2 = " bad_certificate_status_response";
                        break;
                    case 114:
                        str_details2 = " bad_certificate_hash_value";
                        break;
                }
            }
        }

        if (content_type == 22) /* Handshake */
        {
            str_details1 = "???";

            if (len > 0)
            {
                switch (((const unsigned char*)buf)[0])
                {
                    case 0:
                        str_details1 = ", HelloRequest";
                        break;
                    case 1:
                        str_details1 = ", ClientHello";
                        break;
                    case 2:
                        str_details1 = ", ServerHello";
                        break;
                    case 3:
                        str_details1 = ", HelloVerifyRequest";
                        break;
                    case 11:
                        str_details1 = ", Certificate";
                        break;
                    case 12:
                        str_details1 = ", ServerKeyExchange";
                        break;
                    case 13:
                        str_details1 = ", CertificateRequest";
                        break;
                    case 14:
                        str_details1 = ", ServerHelloDone";
                        break;
                    case 15:
                        str_details1 = ", CertificateVerify";
                        break;
                    case 16:
                        str_details1 = ", ClientKeyExchange";
                        break;
                    case 20:
                        str_details1 = ", Finished";
                        break;
                }
            }
        }
    }

    dv_print(&out, "%s %s %s%s%s\n",
            str_version,
            write_p ? "TX" : "RX",
            str_content_type,
            str_details1,
            str_details2);

    dv_append_hex_dump(&out, dv_char2((char*) buf, len), false);

    fprintf(stderr, "%.*s\n", DV_PRI(out));
    dv_free(out);
}

int main(void) {
	SSL_CTX *ctx;
	int fd;
	spdy_connection* c;
	spdy_stream* s;
	spdy_request r;
	fd_set read, write;

#ifdef _WIN32
	WSADATA wsadata;
	WSAStartup(MAKEWORD(2,2), &wsadata);
#endif

	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	ctx = SSL_CTX_new(TLSv1_client_method());

	SSL_CTX_set_msg_callback(ctx, &SSL_MsgCallback);

	c = spdyC_connect("www.foobar.co.nz:443", ctx, &fd);
	spdyC_on_send_wait(c, &send_wait, NULL);

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

		if (FD_ISSET(fd, &read)) {
			spdyC_recv_ready(c);
		}

		if (FD_ISSET(fd, &write)) {
			spdyC_send_ready(c);
		}
	}

	return 0;
}

