/* vim: set noet sts=8 ts=8 sw=8 tw=78: */
#pragma once

#include <openssl/bio.h>

#ifdef SPDY_USE_DMEM
#include <dmem/char.h>
typedef d_Slice(char) spdy_string;
#else
/* Will not be null terminated */
typedef struct {
	int size;
	const char* data;
} spdy_string;
#endif

/* Define this if you get HTTP_* defines from another library */
#ifndef SPDY_NO_HTTP_DEFINES
enum {
	HTTP_CONTINUE = 100,
	HTTP_SWITCHING_PROTOCOLS = 101,

	HTTP_OK = 200,
	HTTP_CREATED = 201,
	HTTP_ACCEPTED = 202,
	HTTP_NON_AUTHORITATIVE_INFO = 203,
	HTTP_NO_CONTENT = 204,
	HTTP_RESET_CONTENT = 205,
	HTTP_PARTIAL_CONTENT = 206,

	HTTP_MULTIPLE_CHOICES = 300,
	HTTP_MOVED_PERMANENTLY = 301,
	HTTP_FOUND = 302,
	HTTP_SEE_OTHER = 303,
	HTTP_NOT_MODIFIED = 304,
	HTTP_USE_PROXY = 305,
	HTTP_TEMPORARY_REDIRECT = 307,

	HTTP_BAD_REQUEST = 400,
	HTTP_UNAUTHORIZED = 401,
	HTTP_PAYMENT_REQUIRED = 402,
	HTTP_FORBIDDEN = 403,
	HTTP_NOT_FOUND = 404,
	HTTP_METHOD_NOT_ALLOWED = 405,
	HTTP_NOT_ACCEPTABLE = 406,
	HTTP_PROXY_AUTH_REQUIRED = 407,
	HTTP_REQUEST_TIMEOUT = 408,
	HTTP_CONFLICT = 409,
	HTTP_GONE = 410,
	HTTP_LENGTH_REQUIRED = 411,
	HTTP_PRECONDITION_FAILED = 412,
	HTTP_REQUEST_ENTITY_TOO_LARGE = 413,
	HTTP_REQUEST_URI_TOO_LONG = 414,
	HTTP_UNSUPPORTED_MEDIA_TYPE = 415,
	HTTP_REQUESTED_RANGE_NOT_SATISFIABLE = 416,
	HTTP_EXPECTATION_FAILED = 417,

	HTTP_INTERNAL_SERVER_ERROR = 500,
	HTTP_NOT_IMPLEMENTED = 501,
	HTTP_BAD_GATEWAY = 502,
	HTTP_SERVICE_UNAVAILABLE = 503,
	HTTP_GATEWAY_TIMEOUT = 504,
	HTTP_VERSION_NOT_SUPPORTED = 505
};
#endif

enum {
	SPDY_FINISHED              = 1,
	SPDY_CONTINUE              = 0,
	SPDY_PROTOCOL              = -1,
	SPDY_INVALID_STREAM        = -2,
	SPDY_REFUSED_STREAM        = -3,
	SPDY_UNSUPPORTED_VERSION   = -4,
	SPDY_CANCEL                = -5,
	SPDY_FLOW_CONTROL          = -6,
	SPDY_STREAM_IN_USE         = -7,
	SPDY_STREAM_ALREADY_CLOSED = -8,
	SPDY_GO_AWAY               = -20,
	SPDY_CONNECTION_CLOSED     = -21,
	SPDY_API                   = -22
};

typedef struct spdy_stream spdy_stream;
typedef struct spdy_connection spdy_connection;
typedef struct spdy_request spdy_request;
typedef struct spdy_reply spdy_reply;
typedef struct spdy_headers spdy_headers;

struct spdy_request {
	unsigned finished : 1;
	unsigned unidirectional : 1;
	spdy_string method;        /* eg GET */
	spdy_string scheme;        /* eg https */
	spdy_string host;          /* eg example.com */
	spdy_string path;          /* eg /foo/bar?val=3 - always has leading / */
	spdy_string protocol;      /* eg HTTP/1.1 */
	spdy_headers* headers;
	int priority;              /* 0 is default priority, -ve is higher like nice values */
};

struct spdy_reply {
	unsigned finished : 1;
	int status;                /* eg 220 */
	spdy_string status_string; /* eg Bad Gateway */
	spdy_string protocol;      /* eg HTTP/1.1 */
	spdy_headers* headers;
};

typedef void (*spdy_fn)(void*);
typedef void (*spdy_send_wait_fn)(void*, int enable);
typedef void (*spdy_data_fn)(void*, int sts, spdy_string, int compressed);
typedef void (*spdy_request_fn)(void*, spdy_stream*, spdy_request*);
typedef void (*spdy_reply_fn)(void*, spdy_reply*);

spdy_stream* spdyS_new(void);
void spdyS_ref(spdy_stream* s);
void spdyS_deref(spdy_stream* s);

int spdyS_start(spdy_stream* parent, spdy_stream* s, spdy_request* r);
int spdyS_reply(spdy_stream* s, spdy_reply* r);
int spdyS_send(spdy_stream* s, spdy_string data, int compressed);
int spdyS_close(spdy_stream* s);
int spdyS_recv_ready(spdy_stream* s, int size);

void spdyS_on_recv(spdy_stream* s, spdy_data_fn cb, void* user);
void spdyS_on_reply(spdy_stream* s, spdy_reply_fn cb, void* user);
void spdyS_on_request(spdy_stream* s, spdy_request_fn cb, void* user);
void spdyS_on_send_ready(spdy_stream* s, spdy_fn cb, void* user);


spdy_connection* spdyC_new(BIO* io, int io_close);
void spdyC_free(spdy_connection* c);

int spdyC_send_ready(spdy_connection* c);
int spdyC_recv_ready(spdy_connection* c);
void spdyC_on_send_wait(spdy_connection* c, spdy_send_wait_fn cb, void* user);

int spdyC_start(spdy_connection* c, spdy_stream* s, spdy_request* r);
void spdyC_on_request(spdy_connection* c, spdy_request_fn cb, void* user);

spdy_connection* spdyC_connect(const char* host, SSL_CTX* ctx, int* fd);
spdy_connection* spdyC_accept(int sfd, SSL_CTX* ctx, int* fd);

spdy_headers* spdyH_new(void);
void spdyH_reset(spdy_headers* h);
void spdyH_free(spdy_headers* h);

/* Note spdy_headers does _not_ clone the actual string contents. Repeats of
 * the same key should be set a single null separated value.
 */
spdy_string spdyH_get(spdy_headers* h, const char* key);
void spdyH_del(spdy_headers* h, const char* key);
void spdyH_set(spdy_headers* h, const char* key, spdy_string val);

/* Will return all the headers for each key as a null separated string. The
 * initial value of idx must be -1.
 */
int spdyH_next(spdy_headers* h, int* idx, const char** key, spdy_string* val);



