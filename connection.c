/* vim: set noet sts=8 ts=8 sw=8 tw=78: */


#ifdef _WIN32
#include <WinSock2.h>
#else
#include <sys/socket.h>
#endif

#define SPDY_USE_DMEM
#include <spdy.h>
#include "packets.h"
#include <dmem/hash.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <zlib.h>
#include <assert.h>

#ifdef _MSC_VER
#define ref(p) _InterlockedIncrement(p)
#define deref(p) _InterlockedDecrement(p)
#else
#define ref(p) __sync_add_and_fetch(p, 1)
#define deref(p) __sync_add_and_fetch(p, 1)
#endif

#define DEFAULT_PROTOCOL C("HTTP/1.1")
#define STATUS_OK C("200 OK")

DVECTOR_INIT(stream, spdy_stream*);
DHASH_INIT_INT(stream, spdy_stream*);

enum state {
	FINISHED,
	WAIT_REPLY,
	WAIT_FIRST_DATA,
	WAIT_DATA,
	WAIT_SOCKET,
	WAIT_WINDOW
};

struct spdy_stream {
	volatile long ref;

	int id;
	int err;
	spdy_connection* connection;

	enum state rx;
	enum state tx;

	bool rx_compressed;
	bool tx_compressed;

	int user_rx_window;
	int remote_rx_window;

	int tx_window;
	int tx_priority;

	spdy_stream* parent;
	d_Vector(stream) children;

	spdy_data_fn recv;
	void* recv_user;

	spdy_reply_fn reply;
	void* reply_user;

	spdy_request_fn request;
	void* request_user;

	spdy_fn send_ready;
	void* send_ready_user;
};

struct spdy_connection {
	d_Vector(char) tbuf;
	d_Vector(char) rbuf;

	d_Vector(char) hdrbuf;
	spdy_headers* headers;

	d_Vector(char) sbuf;

	z_stream zin;
	z_stream zout;

	int next_stream;
	int next_ping;
	int last_remote_stream;

	BIO* io;
	bool io_close;

	bool go_away;
	bool flushing;

	int write_after_read;
	int read_after_write;

	int waiting_for_write;

	int default_rx_window;
	int default_tx_window;

	d_IntHash(stream) streams;
	d_Vector(stream) pstreams[NUM_PRIORITIES];
	spdy_stream* immediate_stream;

	spdy_send_wait_fn send_wait;
	void* send_wait_user;

	spdy_request_fn request;
	void* request_user;
};

static void Log(spdy_connection* c, const char* format, ...) DMEM_PRINTF(2, 3);

static void Log(spdy_connection* c, const char* format, ...) {
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
}

static void log_headers(spdy_connection* c, spdy_headers* h) {
	const char* key;
	d_Slice(char) val;
	int i = -1;
	while (h && spdyH_next(h, &i, &key, &val)) {
		Log(c, "\t%s: %.*s\n", key, DV_PRI(val));
	}
}

static void log_syn_stream(spdy_connection* c, const char* dir, struct syn_stream* f) {
	Log(c, "spdy: %s SYN_STREAM %d, Fin %d, Uni %d, Assoc %d, Pri %d, Url %.*s %.*s %.*s://%.*s%.*s\n",
			dir,
		       	f->stream,
			f->finished,
			f->unidirectional,
		       	f->associated_stream,
		       	f->priority,
			DV_PRI(f->protocol),
			DV_PRI(f->method),
			DV_PRI(f->scheme),
			DV_PRI(f->host),
			DV_PRI(f->path));

	log_headers(c, f->headers);
}

static void log_syn_reply(spdy_connection* c, const char* dir, struct syn_reply* f) {
	Log(c, "spdy: %s SYN_REPLY %d, Fin %d, Rep %.*s %.*s\n",
			dir,
			f->stream,
			f->finished,
			DV_PRI(f->protocol),
			DV_PRI(f->status));

	log_headers(c, f->headers);
}

static void log_data(spdy_connection* c, const char* dir, struct data* f) {
	Log(c, "spdy: %s DATA %d, Fin %d, Zip %d, Len %d\n",
		       	dir,
			f->stream,
		       	f->finished,
		       	f->compressed,
		       	f->size);
}

static void log_window(spdy_connection* c, const char* dir, int stream, int delta) {
	Log(c, "spdy: %s WINDOW_UPDATE %d, Delta %d\n", dir, stream, delta);
}

static void log_ping(spdy_connection* c, const char* dir, uint32_t id) {
	Log(c, "spdy: %s PING %u", dir, (unsigned int) id);
}

static const char* reason_string(int err) {
	switch (err) {
	case SPDY_PROTOCOL:                return "protocol";
	case SPDY_INVALID_STREAM:          return "invalid stream";
	case SPDY_REFUSED_STREAM:          return "refused stream";
	case SPDY_UNSUPPORTED_VERSION:     return "unsupported version";
	case SPDY_CANCEL:                  return "cancel";
	case SPDY_FLOW_CONTROL:            return "flow control";
	case SPDY_STREAM_IN_USE:           return "stream in use";
	case SPDY_STREAM_ALREADY_CLOSED:   return "stream already closed";
	case SPDY_GO_AWAY:                 return "go away";
	case SPDY_CONNECTION_CLOSED:       return "connection closed";
	case SPDY_API:                     return "invalid API usage";
	default:                          return "unknown";
	}
}

static void log_rst_stream(spdy_connection* c, const char* dir, int stream, int reason) {
	Log(c, "spdy %s RST_STREAM %d, %d %s", dir, stream, reason, reason_string(reason));
}

static int log_ssl_error(const char* str, size_t len, void* u) {
	spdy_connection* c = (spdy_connection*) u;
	Log(c, "ssl: %.*s\n", (int) len, str);
	return len;
}

spdy_connection* spdyC_new(BIO* io, int io_close) {
	spdy_connection* c = (spdy_connection*) calloc(1, sizeof(spdy_connection));

	deflateInit(&c->zout, Z_BEST_COMPRESSION);
	deflateSetDictionary(&c->zout, (uint8_t*) DICTIONARY, strlen(DICTIONARY));

	inflateInit(&c->zin);

	c->io = io;
	c->io_close = io_close != 0;

	/* Default setup is for a client, we auto detect a server in
	 * handle_syn_stream
	 */
	c->next_stream = 1;
	c->next_ping = 1;

	c->default_rx_window = DEFAULT_WINDOW;
	c->default_tx_window = DEFAULT_WINDOW;

	c->headers = spdyH_new();

	return c;
}

spdy_stream* spdyS_new(void) {
	spdy_stream* s = (spdy_stream*) calloc(1, sizeof(spdy_stream));
	s->err = SPDY_API;
	return s;
}

void spdyS_ref(spdy_stream* s) {
	(void) ref(&s->ref);
}

void spdyS_deref(spdy_stream* s) {
	if (s && deref(&s->ref) == 0) {
		assert(s->connection == NULL);
		dv_free(s->children);
		free(s);
	}
}

static void finish_stream(spdy_connection* c, spdy_stream* s, int si, int err) {
	int i;
	s->err = err;
	s->connection = NULL;

	if (s->tx == WAIT_SOCKET) {
		d_Vector(stream)* p = &c->pstreams[s->tx_priority];
		dv_find(*p, s, &i);
		assert(i >= 0);
		if (c->flushing) {
			/* flusher will pick this up next round */
			p->data[i] = NULL;
		} else {
			p->data[i] = p->data[p->size-1];
			dv_erase_end(p, 1);
		}
	}

	s->tx = FINISHED;

	if (s->rx != FINISHED && s->recv) {
		d_Slice(char) end = DV_INIT;
		s->recv(s->recv_user, err, end, s->rx_compressed);
	}

	s->rx = FINISHED;

	assert(si >= 0);
	dh_erase(&c->streams, si);

	if (s->parent) {
		dv_find(s->parent->children, s, &i);
		assert(i >= 0);
		dv_erase(&s->parent->children, i, 1);
		s->parent = NULL;
	}

	for (i = 0; i < s->children.size; i++) {
		int ci;
		spdy_stream* ch = s->children.data[i];
		dhi_find(&c->streams, ch->id, &ci);
		ch->parent = NULL;
		finish_stream(c, s->children.data[i], ci, err);
	}
	dv_clear(&s->children);

	if (s->recv) {
		d_Slice(char) end = DV_INIT;
		s->recv(s->recv_user, err, end, s->rx_compressed ? 1 : 0);
	}

	spdyS_deref(s);
}

void spdyC_free(spdy_connection* c) {
	int i;
	if (!c) {
		return;
	}

	/* Stop new streams from being created, otherwise we can't safely
	 * iterate over c->streams.
	 */
	c->go_away = true;

	spdyS_deref(c->immediate_stream);

	i = -1;
	while (dh_hasnext(&c->streams, &i)) {
		spdy_stream* s = c->streams.vals[i];
		/* We only need to stop the root streams, finish_stream will
		 * clean up the children recursively
		 */
		if (s->parent == NULL) {
			finish_stream(c, s, i, SPDY_CONNECTION_CLOSED);
		}
	}
	dh_free(&c->streams);

	for (i = 0; i < NUM_PRIORITIES; i++) {
		dv_free(c->pstreams[i]);
	}

	spdyH_free(c->headers);
	dv_free(c->hdrbuf);
	dv_free(c->tbuf);
	dv_free(c->sbuf);
	dv_free(c->rbuf);

	deflateEnd(&c->zout);
	inflateEnd(&c->zin);

	if (c->io_close) {
		BIO_free_all(c->io);
	}

	free(c);
}

static int flush_recv(spdy_connection* c);

static int flush_tbuf(spdy_connection* c) {
	int sent;

	c->write_after_read = 0;
	sent = BIO_write(c->io, c->tbuf.data, c->tbuf.size);

	/* Remove any data that was sent from the buffer */
	if (sent > 0) {
		dv_erase(&c->tbuf, 0, sent);
	}

	/* Check to see why we couldn't send all of the data */
	if (c->tbuf.size) {
		if (!BIO_should_retry(c->io)) {
			ERR_print_errors_cb(&log_ssl_error, c);
			return -1;
		}

		c->write_after_read = BIO_should_read(c->io);

		if (c->waiting_for_write != BIO_should_write(c->io)) {
			c->waiting_for_write = !c->waiting_for_write;
			if (c->send_wait) {
				c->send_wait(c->send_wait_user, c->waiting_for_write);
			}
		}

	} else if (c->waiting_for_write) {
		c->waiting_for_write = 0;
		if (c->send_wait) {
			c->send_wait(c->send_wait_user, 0);
		}
	}

	if (c->read_after_write) {
		return flush_recv(c);
	}

	return 0;
}

static int send_reset(spdy_connection* c, int stream, int reason) {
	log_rst_stream(c, "tx", stream, reason);
	marshal_rst_stream(&c->tbuf, stream, reason);
	return flush_tbuf(c);
}

static int start(spdy_connection* c, spdy_stream* p, spdy_stream* s, spdy_request* r) {
	struct syn_stream f;
	int err;
	/* Note: s may be NULL if r->finished && r->unidirectional */

	if (c->go_away || c->next_stream >= MAX_STREAM_ID) {
		return SPDY_GO_AWAY;
	}

	if (s == NULL && !(r->finished && r->unidirectional)) {
		return SPDY_API;
	}

	f.stream = c->next_stream;
	f.finished = r->finished;
	f.unidirectional = r->unidirectional;
	f.associated_stream = p ? p->id : 0;
	f.priority = r->priority + DEFAULT_PRIORITY;
	f.headers = r->headers;
	f.scheme = r->scheme.size ? r->scheme : C("https");
	f.protocol = r->protocol.size ? r->protocol : DEFAULT_PROTOCOL;
	f.method = r->method.size ? r->method : C("GET");
	f.path = r->path;
	f.host = r->host;

	if (f.priority < 0) {
		f.priority = 0;
	} else if (f.priority >= NUM_PRIORITIES) {
		f.priority = NUM_PRIORITIES - 1;
	}

	log_syn_stream(c, "tx", &f);
	marshal_syn_stream(&c->tbuf, &f, &c->zout);
	err = flush_tbuf(c);
	if (err) return err;

	c->next_stream += 2;

	/* unidirectional and immediate finish messages never
	 * get added to the streams table
	 */
	if (r->finished && r->unidirectional) {
		return 0;
	}

	/* Setup stream */
	s->connection = c;
	s->id = f.stream;
	s->err = 0;
	s->tx = r->finished ? FINISHED : WAIT_FIRST_DATA;
	s->rx = r->unidirectional ? FINISHED : WAIT_REPLY;
	s->rx_compressed = s->tx_compressed = false;
	s->user_rx_window = s->remote_rx_window = c->default_rx_window;
	s->tx_window = c->default_tx_window;
	s->tx_priority = f.priority;

	/* Add to stream table */
	spdyS_ref(s);
	dhi_set(&c->streams, s->id, s);

	s->parent = p;
	if (p) {
		dv_append1(&p->children, s);
	}

	return 0;
}

int spdyC_start(spdy_connection* c, spdy_stream* s, spdy_request* r) {
	return start(c, NULL, s, r);
}

int spdyS_start(spdy_stream* p, spdy_stream* s, spdy_request* r) {
	if (p->err) {
		return p->err;
	}
	return start(p->connection, p, s, r);
}

static int handle_syn_stream(spdy_connection* c, d_Slice(char) d) {
	spdy_request_fn cb = c->request;
	void* user = c->request_user;
	spdy_stream* parent = NULL;
	spdy_stream* s;
	struct syn_stream f;
	spdy_request r;
	int err;
	int si;

	f.headers = c->headers;
	err = parse_syn_stream(&f, d, &c->zin, &c->hdrbuf);
	if (err) return err;

	log_syn_stream(c, "rx", &f);

	/* The remote has reopened an already opened stream. We kill both.
	 * Check this first as if any other check fails and this would've also
	 * failed sending out the reset will invalidate the existing stream.
	 *
	 * Messages that have both their rx and tx pipes already closed don't
	 * need to be added to the streams table.
	 */
	if ((f.finished && f.unidirectional)
	       	? dhi_find(&c->streams, f.stream, &si)
		: !dhi_add(&c->streams, f.stream, &si)) {

		err = send_reset(c, f.stream, SPDY_STREAM_IN_USE);
		finish_stream(c, c->streams.vals[si], si, SPDY_STREAM_IN_USE);
		return err;
	}

	/* After a go away has been sent/received, we just ignore incoming
	 * streams
	 */
	if (c->go_away) {
		return 0;
	}

	/* Detect that we are the server */
	if (c->next_stream == 1 && c->last_remote_stream == 0 && (f.stream & 1)) {
		c->next_stream = 2;
		c->next_ping = 0;
	}

	/* The remote tried to open a stream of the wrong type (eg its a
	 * client and tried to open a server stream).
	 */
	if ((f.stream & 1) == (c->next_stream & 1)) {
		err = SPDY_PROTOCOL;
		goto reset;
	}

	/* Stream Ids must monotonically increase */
	if (f.stream <= c->last_remote_stream) {
		err = SPDY_PROTOCOL;
		goto reset;
	}

	if (f.associated_stream > 0) {
		/* You are only allowed to open associated streams to streams
		 * that you are the recipient.
		 */
		if ((f.associated_stream & 1) != (c->next_stream & 1)) {
			err = SPDY_PROTOCOL;
			goto reset;
		}

		/* The remote tried to open a stream associated with a closed
		 * stream. We kill this new stream.
		 */
		if (!dhi_get(&c->streams, f.associated_stream, &parent)) {
			err = SPDY_INVALID_STREAM;
			goto reset;
		}

		cb = parent->request;
		user = parent->request_user;
	}

	if (cb == NULL) {
		err = SPDY_REFUSED_STREAM;
		goto reset;
	}

	/* The SYN_STREAM passed all of our tests, so go ahead and create the
	 * stream and hook it up.
	 */

	r.finished = f.finished;
	r.unidirectional = f.unidirectional;
	r.method = f.method;
	r.scheme = f.scheme;
	r.host = f.host;
	r.path = f.path;
	r.protocol = f.protocol;
	r.headers = f.headers;
	r.priority = f.priority - DEFAULT_PRIORITY;

	/* Messages that have both their rx and tx pipes already closed don't
	 * need to be added to the streams table.
	 */
	if (f.finished && f.unidirectional) {
		/* Use a cached stream */
		if (c->immediate_stream) {
			s = c->immediate_stream;
			c->immediate_stream = NULL;
			deref(&s->ref);
		} else {
			s = spdyS_new();
		}

	} else {
		s = spdyS_new();

		spdyS_ref(s);
		c->streams.vals[si] = s;

		if (parent != NULL) {
			s->parent = parent;
			dv_append1(&parent->children, s);
		}
	}

	/* Setup the stream */
	s->connection = c;
	s->id = f.stream;
	s->err = 0;
	s->tx = f.unidirectional ? FINISHED : WAIT_REPLY;
	s->rx = f.finished ? FINISHED : WAIT_FIRST_DATA;
	s->rx_compressed = s->tx_compressed = false;
	s->user_rx_window = c->default_rx_window;
	s->remote_rx_window = c->default_rx_window;
	s->tx_window = c->default_tx_window;
	s->tx_priority = f.priority;
	s->recv = NULL;
	s->reply = NULL;
	s->request = NULL;
	s->send_ready = NULL;

	/* Notify the user of the new request */
	spdyS_ref(s);
	cb(user, s, &r);

	/* Try and put immediate streams back into the cache */
	if (!(f.finished && f.unidirectional)) {
		spdyS_deref(s);
		return 0;
	}

	/* The user has taken control of this stream */
	if (deref(&s->ref) > 0) {
		return 0;
	}

	/* Put the stream back in the cache */
	spdyS_ref(s);
	c->immediate_stream = s;
	return 0;

reset:
	dh_erase(&c->streams, si);
	return send_reset(c, f.stream, err);
}

static d_Slice(char) lookup_status(int status, d_Slice(char) str, d_Vector(char)* buf) {
	if (str.size) {
		dv_clear(buf);
		dv_print(buf, "%d %.*s", status, DV_PRI(str));
		return *buf;
	}

	switch (status) {
	case HTTP_CONTINUE:                  return C("100 Continue");
	case HTTP_SWITCHING_PROTOCOLS:       return C("101 Switching Protocols");

	case 0: /* default status if the reply is memset to 0 */
	case HTTP_OK:                        return C("200 OK");
	case HTTP_CREATED:		     return C("201 Created");
	case HTTP_ACCEPTED:                  return C("202 Accepted");
	case HTTP_NON_AUTHORITATIVE_INFO:    return C("203 Non-Authoritative Information");
	case HTTP_NO_CONTENT:                return C("204 No Content");
	case HTTP_RESET_CONTENT:             return C("205 Reset Content");
	case HTTP_PARTIAL_CONTENT:           return C("206 Partial Content");

	case HTTP_MULTIPLE_CHOICES:          return C("300 Multiple Choices");
	case HTTP_MOVED_PERMANENTLY:         return C("301 Moved Permanently");
	case HTTP_FOUND:                     return C("302 Found");
	case HTTP_SEE_OTHER:                 return C("303 See Other");
	case HTTP_NOT_MODIFIED:              return C("304 Not Modified");
	case HTTP_USE_PROXY:                 return C("305 Use Proxy");
	case HTTP_TEMPORARY_REDIRECT:        return C("307 Temporary Redirect");

	case HTTP_BAD_REQUEST:               return C("400 Bad Request");
	case HTTP_UNAUTHORIZED:              return C("401 Unauthorized");
	case HTTP_PAYMENT_REQUIRED:          return C("402 Payment Required");
	case HTTP_FORBIDDEN:                 return C("403 Forbidden");
	case HTTP_NOT_FOUND:                 return C("404 Not Found");
	case HTTP_METHOD_NOT_ALLOWED:        return C("405 Method Not Allowed");
	case HTTP_NOT_ACCEPTABLE:            return C("406 Not Acceptable");
	case HTTP_PROXY_AUTH_REQUIRED:       return C("407 Proxy Authentication Required");
	case HTTP_REQUEST_TIMEOUT:           return C("408 Request Timeout");
	case HTTP_CONFLICT:                  return C("409 Conflict");
	case HTTP_GONE:                      return C("410 Gone");
	case HTTP_LENGTH_REQUIRED:           return C("411 Length Required");
	case HTTP_PRECONDITION_FAILED:       return C("412 Precondition Failed");
	case HTTP_REQUEST_ENTITY_TOO_LARGE:  return C("413 Request Entity Too Large");
	case HTTP_REQUEST_URI_TOO_LONG:      return C("414 Request URI Too Long");
	case HTTP_UNSUPPORTED_MEDIA_TYPE:    return C("415 Unsupported Media Type");
	case HTTP_REQUESTED_RANGE_NOT_SATISFIABLE: return C("416 Requested Range Not Satisfiable");
	case HTTP_EXPECTATION_FAILED:        return C("417 Expectation Failed");

	case HTTP_INTERNAL_SERVER_ERROR:     return C("418 Internal Server Error");
	case HTTP_NOT_IMPLEMENTED:           return C("419 Not Implemented");
	case HTTP_BAD_GATEWAY:               return C("420 Bad Gateway");
	case HTTP_SERVICE_UNAVAILABLE:       return C("421 Service Unavailable");
	case HTTP_GATEWAY_TIMEOUT:           return C("422 Gateway Timeout");
	case HTTP_VERSION_NOT_SUPPORTED:     return C("423 HTTP Version Not Supported");

	default:
		dv_clear(buf);
		dv_print(buf, "%d", status);
		return *buf;
	}

}

int spdyS_reply(spdy_stream* s, spdy_reply* r) {
	spdy_connection* c = s->connection;
	struct syn_reply f;

	if (s->tx == FINISHED) {
		return SPDY_STREAM_ALREADY_CLOSED;
	} else if (s->tx != WAIT_REPLY) {
		return SPDY_API;
	}

	if (r->finished) {
		s->tx = FINISHED;
	}

	f.finished = r->finished;
	f.stream = s->id;
	f.headers = r->headers;
	f.status = lookup_status(r->status, r->status_string, &c->sbuf);
	f.protocol = r->protocol.size ? r->protocol : DEFAULT_PROTOCOL;

	log_syn_reply(c, "tx", &f);
	marshal_syn_reply(&c->tbuf, &f, &c->zout);
	return flush_tbuf(c);
}

static int handle_syn_reply(spdy_connection* c, d_Slice(char) d) {
	struct syn_reply f;
	spdy_stream* s;
	spdy_reply r;
	int err, si;

	f.headers = c->headers;
	err = parse_syn_reply(&f, d, &c->zin, &c->hdrbuf);
	if (err) return err;

	log_syn_reply(c, "rx", &f);

	if (!dhi_find(&c->streams, f.stream, &si)) {
		return send_reset(c, f.stream, SPDY_INVALID_STREAM);
	}
	s = c->streams.vals[si];

	/* Can't send a reply to your own request */
	if ((f.stream & 1) != (c->next_stream & 1)) {
		err = send_reset(c, f.stream, SPDY_PROTOCOL);
		finish_stream(c, s, si, SPDY_PROTOCOL);
		return err;
	}

	switch (s->rx) {
	case FINISHED:
		err = send_reset(c, f.stream, SPDY_STREAM_ALREADY_CLOSED);
		finish_stream(c, s, si, SPDY_STREAM_ALREADY_CLOSED);
		return err;

	case WAIT_FIRST_DATA:
	case WAIT_DATA:
		err = send_reset(c, f.stream, SPDY_STREAM_IN_USE);
		finish_stream(c, s, si, SPDY_STREAM_IN_USE);
		return err;

	case WAIT_REPLY:
		break;
	default:
		assert(0);
	}

	r.status_string = f.status;
	r.protocol = f.protocol;
	r.headers = f.headers;

	{
		d_Slice(char) code = dv_split_left(&r.status_string, ' ');
		r.status = dv_to_integer(code, 10, -1);

		if (code.size == 0 || r.status < 0) {
			err = send_reset(c, f.stream, SPDY_PROTOCOL);
			finish_stream(c, s, si, SPDY_PROTOCOL);
			return err;
		}
	}

	s->rx = WAIT_FIRST_DATA;

	if (s->reply) {
		s->reply(s->reply_user, &r);
	}

	if (f.finished && s->tx == FINISHED) {
		int si;
		dhi_find(&c->streams, s->id, &si);
		finish_stream(c, s, si, SPDY_FINISHED);
	} else if (f.finished) {
		s->rx = FINISHED;
	}

	return 0;
}

static int handle_rst_stream(spdy_connection* c, d_Slice(char) d) {
	int reason, stream, si, err;
	spdy_stream* s;

	err = parse_rst_stream(&stream, &reason, d);
	if (err) return err;

	log_rst_stream(c, "rx", stream, reason);

	if (!dhi_find(&c->streams, stream, &si)) {
		/* Don't send resets for closed streams, otherwise the channel
		 * would collapse. */
		return 0;
	}

	s = c->streams.vals[si];
	finish_stream(c, s, si, reason);
	return 0;
}

static int handle_ping(spdy_connection* c, d_Slice(char) d) {
	uint32_t id;
	int err;

	err = parse_ping(&id, d);
	if (err) return err;

	log_ping(c, "rx", id);

	/* Ignore loopback pings */
	if ((id & 1) == (c->next_ping & 1)) {
		return 0;
	}

	log_ping(c, "tx", id);
	marshal_ping(&c->tbuf, id);
	return flush_tbuf(c);
}

static int flush_send(spdy_connection* c) {
	int i, err;

	/* Try and flush what we already have buffered */
	err = flush_tbuf(c);
	if (err || c->waiting_for_write || c->write_after_read) {
		return err;
	}

	/* We have flushed the tx buffer, so now try and flush streams that
	 * are waiting to send. We choose streams randomly in each priority
	 * level, but finish all streams in a given priority before going on
	 * to the next. Set the flushing value to stop finish_stream
	 * from removing streams from pstreams whilst we iterate over it.
	 */
	c->flushing = true;
	for (i = 0; i < NUM_PRIORITIES && !c->waiting_for_write && !c->write_after_read; i++) {
		d_Vector(stream)* v = &c->pstreams[i];
		int left = v->size;

		while (left > 0 && !c->waiting_for_write && !c->write_after_read) {
			int j = rand() % left;
			spdy_stream* s = v->data[j];

			/* Need to hold a ref in case it finishes in the
			 * callback
			 */
			if (s) {
				assert(s->tx == WAIT_SOCKET);
				spdyS_ref(s);
				if (s->send_ready) {
					s->send_ready(s->send_ready_user);
				}
			}

			/* Compact the remaining streams to be processed to
			 * the head of the vector.
			 */
			v->data[j] = v->data[left-1];
			v->data[left-1] = s;

			/* This stream gets removed from the vector if it
			 * managed to fully flush, changed priorities or was
			 * closed.
			 */
			if (v->data[left-1] == NULL) {
				assert(s == NULL || s->tx != WAIT_SOCKET);
				v->data[left-1] = v->data[v->size-1];
				dv_erase_end(v, 1);
			}

			left--;
			spdyS_deref(s);
		}
	}
	c->flushing = false;

	return 0;
}

static int handle_window_update(spdy_connection* c, d_Slice(char) d) {
	int stream, delta, err;
	spdy_stream* s;

	err = parse_window(&stream, &delta, d);
	if (err) return err;

	log_window(c, "rx", stream, delta);

	if (!dhi_get(&c->streams, stream, &s)) {
		return send_reset(c, stream, SPDY_INVALID_STREAM);
	}

	s->tx_window += delta;

	if (s->tx != WAIT_WINDOW) {
		return 0;
	}

	/* If we were waiting on the window, figure out what we are now
	 * waiting on.
	 */

	if (c->waiting_for_write || c->write_after_read) {
		/* Now waiting on the socket */
		s->tx = WAIT_SOCKET;
		dv_append1(&c->pstreams[s->tx_priority], s);
	} else {
		/* Now waiting on the user */
		s->tx = WAIT_DATA;
		if (s->send_ready) {
			s->send_ready(s->send_ready_user);
		}
	}

	return 0;
}

int spdyS_cancel(spdy_stream* s) {
	spdy_connection* c = s->connection;
	int si, err, reason;

	if (s->err) {
		return s->err;
	}

	reason = ((s->id & 1) == (c->next_stream & 1))
		? SPDY_CANCEL
	       	: SPDY_REFUSED_STREAM;

	err = send_reset(c, s->id, reason);

	dhi_find(&c->streams, s->id, &si);
	finish_stream(c, s, si, reason);

	return err;
}

int spdyS_send_close(spdy_stream* s) {
	spdy_connection* c = s->connection;
	struct syn_reply rf;
	struct data df;

	if (s->err) {
		return s->err;
	}

	switch (s->tx) {
	case FINISHED:
		return SPDY_STREAM_ALREADY_CLOSED;

	case WAIT_REPLY:
		/* Send an empty reply with the finished flag set */
		rf.finished = true;
		rf.stream = s->id;
		rf.headers = NULL;
		rf.status = STATUS_OK;
		rf.protocol = DEFAULT_PROTOCOL;
		log_syn_reply(c, "tx", &rf);
		marshal_syn_reply(&c->tbuf, &rf, &c->zout);
		break;

	case WAIT_SOCKET:
	case WAIT_WINDOW:
	case WAIT_FIRST_DATA:
	case WAIT_DATA:
		/* Send an empty data frame with the finished flag set */
		df.finished = true;
		df.compressed = s->tx_compressed;
		df.stream = s->id;
		df.size = 0;
		log_data(c, "tx", &df);
		dv_append_buffer(&c->tbuf, DATA_HEADER_SIZE);
		marshal_data_header(c->tbuf.data + c->tbuf.size - DATA_HEADER_SIZE, &df);
		break;

	default:
		assert(0);
	}

	s->tx = FINISHED;

	/* Remove the stream from the connection if we are now all finished */
	if (s->tx == FINISHED && s->rx == FINISHED) {
		int si;
		dhi_find(&c->streams, s->id, &si);
		finish_stream(c, s, si, SPDY_STREAM_ALREADY_CLOSED);
	}

	return flush_tbuf(c);
}

int spdyS_send(spdy_stream* s, d_Slice(char) data, int compressed) {
	spdy_connection* c = s->connection;
	int begin, err;
	spdy_reply r;
	struct data f;

	if (s->err) {
		return s->err;
	}

	switch (s->tx) {
	case FINISHED:
		return SPDY_STREAM_ALREADY_CLOSED;

	case WAIT_SOCKET:
	case WAIT_WINDOW:
		return 0;

	case WAIT_REPLY:
		memset(&r, 0, sizeof(r));
		err = spdyS_reply(s, &r);
		if (err) return err;
		/* fallthrough */
	case WAIT_FIRST_DATA:
		s->tx_compressed = compressed;
		s->tx = WAIT_DATA;
		/* fallthrough */
	case WAIT_DATA:
		break;

	default:
		assert(0);
	}

	assert(s->tx == WAIT_DATA);

	if (s->tx_compressed != compressed) {
		spdyS_cancel(s);
		return SPDY_API;
	}

	if (c->waiting_for_write || c->write_after_read) {
		s->tx = WAIT_SOCKET;
		dv_append1(&c->pstreams[s->tx_priority], s);
		return 0;
	}

	if (data.size > s->tx_window) {
		s->tx = WAIT_WINDOW;
		data.size = s->tx_window;
	}

	if (!data.size) {
		return 0;
	}

	f.finished = false;
	f.compressed = false;
	f.stream = s->id;
	f.size = data.size;

	log_data(c, "tx", &f);

	begin = c->tbuf.size;
	dv_append_buffer(&c->tbuf, DATA_HEADER_SIZE);
	dv_append(&c->tbuf, data);
	marshal_data_header(&c->tbuf.data[begin], &f);

	err = flush_tbuf(c);
	if (err) return err;

	s->tx_window -= data.size;
	return data.size;
}

int spdyS_recv_ready(spdy_stream* s, int size) {
	spdy_connection* c = s->connection;
	int delta;

	if (s->rx == FINISHED) {
		return 0;
	}

	if (s->err) {
		return s->err;
	}

	s->user_rx_window += size;
	delta = s->user_rx_window - s->remote_rx_window;

	if (delta < 0 || size < 0) {
		spdyS_cancel(s);
		return SPDY_API;
	}

	if (delta < DEFAULT_WINDOW/2) {
		return 0;
	}

	log_window(c, "tx", s->id, delta);
	marshal_window(&c->tbuf, s->id, delta);
	return flush_tbuf(c);
}

static int handle_data(spdy_connection* c, d_Slice(char) d) {
	spdy_stream* s;
	struct data f;
	int si, err;

	parse_data(&f, d);
	log_data(c, "rx", &f);

	if (!dhi_find(&c->streams, f.stream, &si)) {
		return send_reset(c, f.stream, SPDY_INVALID_STREAM);
	}
	s = c->streams.vals[si];

	switch (s->rx) {
	case FINISHED:
		err = send_reset(c, f.stream, SPDY_STREAM_ALREADY_CLOSED);
		finish_stream(c, s, si, SPDY_STREAM_ALREADY_CLOSED);
		return err;

	case WAIT_FIRST_DATA:
		s->rx_compressed = f.compressed;
		s->rx = WAIT_DATA;
		break;

	case WAIT_DATA:
		break;

	default:
		assert(0);
	}

	assert(s->rx == WAIT_DATA);

	/* Streams are not allowed to change from compress to non-compress mid
	 * way through
	 */
	if (s->rx_compressed != f.compressed) {
		err = send_reset(c, f.stream, SPDY_PROTOCOL);
		finish_stream(c, s, si, SPDY_PROTOCOL);
		return err;
	}

	if (f.size > s->remote_rx_window) {
		err = send_reset(c, f.stream, SPDY_FLOW_CONTROL);
		finish_stream(c, s, si, SPDY_FLOW_CONTROL);
		return err;
	}

	s->remote_rx_window -= f.size;

	if (f.size > 0 && s->recv) {
		s->rx = f.finished ? FINISHED : WAIT_DATA;
		s->recv(s->recv_user,
			       	f.finished ? SPDY_FINISHED : SPDY_CONTINUE,
				dv_right(d, DATA_HEADER_SIZE),
			       	f.compressed);
	}

	if (f.finished && s->tx == FINISHED) {
		/* re lookup the stream index in case the callback
		 * added streams
		 */
		dhi_find(&c->streams, s->id, &si);
		finish_stream(c, s, si, SPDY_STREAM_ALREADY_CLOSED);

	} else if (f.finished) {
		s->rx = FINISHED;
	}

	return 0;
}

static int parse(spdy_connection* c, uint32_t type, d_Slice(char) d) {
	if (type & FLAG_CONTROL) {
		switch (type) {
		case SYN_STREAM:
			return handle_syn_stream(c, d);
		case SYN_REPLY:
			return handle_syn_reply(c, d);
		case RST_STREAM:
			return handle_rst_stream(c, d);
		case PING:
			return handle_ping(c, d);
		case WINDOW_UPDATE:
			return handle_window_update(c, d);
		default:
			/* ignore unknown messages */
			return 0;
		}
	} else {
		return handle_data(c, d);
	}
}

static int flush_recv(spdy_connection* c) {
	c->read_after_write = 0;
	for (;;) {
		d_Slice(char) d;
		int read;

		if (c->rbuf.size > c->default_rx_window + DATA_HEADER_SIZE) {
			return -1;
		}

		dv_reserve(&c->rbuf, c->rbuf.size + 4096);

		read = BIO_read(c->io, c->rbuf.data + c->rbuf.size, dv_reserved(c->rbuf) - c->rbuf.size);

		if (read <= 0 && !BIO_should_retry(c->io)) {
			ERR_print_errors_cb(&log_ssl_error, c);
			return -1;
		}

		if (c->write_after_read) {
			int err = flush_send(c);
			if (err) return err;
		}

		if (read <= 0) {
			return 0;
		}

		c->rbuf.size += read;
		d = c->rbuf;

		while (d.size >= FRAME_HEADER_SIZE) {
			uint32_t type;
			int length, err;

			parse_frame(&type, &length, d.data);

			if (d.size < length) {
				break;
			}

			err = parse(c, type, dv_left(d, length));
			if (err) return err;
			d = dv_right(d, length);
		}

		dv_set(&c->rbuf, d);
	}
}

int spdyC_send_ready(spdy_connection* c) {
	return flush_send(c);
}

int spdyC_recv_ready(spdy_connection* c) {
	return flush_recv(c);
}

void spdyS_on_recv(spdy_stream* s, spdy_data_fn cb, void* user) {
	s->recv = cb;
	s->recv_user = user;
}

void spdyS_on_reply(spdy_stream* s, spdy_reply_fn cb, void* user) {
	s->reply = cb;
	s->reply_user = user;
}

void spdyS_on_request(spdy_stream* s, spdy_request_fn cb, void* user) {
	s->request = cb;
	s->request_user = user;
}

void spdyS_on_send_ready(spdy_stream* s, spdy_fn cb, void* user) {
	s->send_ready = cb;
	s->send_ready_user = user;
}

void spdyC_on_send_wait(spdy_connection* c, spdy_send_wait_fn cb, void* user) {
	c->send_wait = cb;
	c->send_wait_user = user;
}

void spdyC_on_request(spdy_connection* c, spdy_request_fn cb, void* user) {
	c->request = cb;
	c->request_user = user;
}

#define PROXY_WRITE ((uintptr_t) 1)
#define PROXY_READ ((uintptr_t) 2)
#define PROXY_READ_NL ((uintptr_t) 4)

struct proxy {
	d_Vector(char) tx;
	d_Vector(char) rx;
	int txoff;
	int rxoff;
	bool read;
	bool read_newline;
};

static int proxy_write(BIO *b, const char *buf, int num) {
	struct proxy* c = (struct proxy*) b->ptr;
	int written;

	if (c == NULL || b->next_bio == NULL) {
		return 0;
	}

	if (c->tx.size > c->txoff) {
		written = BIO_write(b->next_bio, c->tx.data + c->txoff, c->tx.size - c->txoff);
		BIO_clear_retry_flags(b);
		BIO_copy_next_retry(b);

		if (written <= 0) {
			return written;
		}

		c->txoff += written;

		if (c->tx.size > c->txoff) {
			BIO_set_retry_write(b);
			return 0;
		}
	}

	written = BIO_write(b->next_bio, buf, num);
	BIO_clear_retry_flags(b);
	BIO_copy_next_retry(b);
	return written;
}

static int proxy_read(BIO *b, char* buf, int size) {
	struct proxy* c = (struct proxy*) b->ptr;
	char *p, *e;
	int read;

	if (size == 0 || c == NULL || b->next_bio == NULL) {
		return 0;
	}

	if (!c->read) {
		if (c->rx.size > c->rxoff) {
			int tocopy = c->rx.size - c->rxoff > size ? size : c->rx.size - c->rxoff;
			memcpy(buf, c->rx.data + c->rxoff, tocopy);
			size -= tocopy;
			buf += tocopy;
			c->rxoff += tocopy;

			if (size == 0) {
				return tocopy;
			}
		}

		read = BIO_read(b->next_bio, buf, size);
		BIO_clear_retry_flags(b);
		BIO_copy_next_retry(b);
		return read;
	}

	dv_reserve(&c->rx, c->rx.size + 512);
	read = BIO_read(b->next_bio, c->rx.data + c->rx.size, dv_reserved(c->rx) - c->rx.size);
	BIO_clear_retry_flags(b);
	BIO_copy_next_retry(b);

	if (read <= 0) {
		return read;
	}

	p = c->rx.data + c->rx.size;
	e = p + read;

	dv_resize(&c->rx, c->rx.size + read);

	if (c->read_newline) {
		goto have_newline;
	}

	/* Consume data until we get two newlines in a row */
	for (;;) {
		p = memchr(p, '\n', e - p);
		if (p == NULL) {
			BIO_set_retry_read(b);
			return 0;
		}

		p++;
		c->read_newline = true;

	have_newline:
		if (p == e) {
			BIO_set_retry_read(b);
			return 0;
		}

		if (*p == '\r') {
			p++;
		}

		if (p == e) {
			BIO_set_retry_read(b);
			return 0;
		}

		if (*p == '\n') {
			int tocopy = e - p > size ? size : e - p;
			c->rxoff = p - c->rx.data + tocopy;
			memcpy(buf, p, tocopy);
			c->read = false;
			return tocopy;
		}

		c->read_newline = false;
	}
}

static int proxy_new(BIO *b) {
	struct proxy* c = (struct proxy*) calloc(1, sizeof(struct proxy));
	c->read = true;
	c->read_newline = false;
	b->ptr = c;
	b->init = 1;
	return 1;
}

static int proxy_free(BIO *b) {
	struct proxy* c = (struct proxy*) b->ptr;
	if (c) {
		dv_free(c->tx);
		dv_free(c->rx);
		free(c);
	}
	b->init = 0;
	return 1;
}

#define SET_PROXY 300

static long proxy_ctrl(BIO* b, int cmd, long larg, void *parg) {
	struct proxy* c = (struct proxy*) b->ptr;

	if (c != NULL && cmd == SET_PROXY) {
		dv_clear(&c->tx);
		dv_print(&c->tx, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
				(char*) parg,
				(char*) parg);
		c->txoff = 0;
	}

	return 0;
}

static BIO_METHOD proxy_method = {
	BIO_TYPE_FILTER,
	"http proxy",
	proxy_write,
	proxy_read,
	NULL,
	NULL,
	proxy_ctrl,
	proxy_new,
	proxy_free,
	NULL,
};

#define NPN "\x06spdy/3"

static int next_proto_cb(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) {
	SSL_select_next_proto(out, outlen, in, inlen, (uint8_t*) NPN, sizeof(NPN)-1);
	return SSL_TLSEXT_ERR_OK;
}

spdy_connection* spdyC_connect(const char* host, SSL_CTX* ctx, int* fd) {
	const char* proxy;
	BIO* io;

	SSL_CTX_set_next_proto_select_cb(ctx, &next_proto_cb, NULL);

	proxy = getenv("http_proxy");
	if (!proxy) {
		proxy = getenv("HTTP_PROXY");
	}

	if (proxy) {
		BIO *prx, *con;
		con = BIO_new(BIO_s_connect());
		BIO_set_conn_hostname(con, proxy);
		BIO_set_nbio(con, 1);
		BIO_do_connect(con);
		BIO_get_fd(con, fd);

		prx = BIO_new(&proxy_method);
		BIO_ctrl(prx, SET_PROXY, 0, (void*) host);

		io = BIO_push(prx, con);
	} else {
		io = BIO_new(BIO_s_connect());
		BIO_set_conn_hostname(io, host);
		BIO_set_nbio(io, 1);
		BIO_do_connect(io);
		BIO_get_fd(io, fd);
	}

	if (ctx) {
		BIO* ssl = BIO_new_ssl(ctx, 1);
		io = BIO_push(ssl, io);
	}

	return spdyC_new(io, true);
}

spdy_connection* spdyC_accept(int sfd, SSL_CTX* ctx, int* fd) {
	BIO *io;
	int cfd;

	cfd = accept(sfd, NULL, NULL);
	if (cfd < 0) {
		return NULL;
	}

	if (fd) {
		*fd = cfd;
	}

	io = BIO_new(BIO_s_fd());
	BIO_set_fd(io, cfd, BIO_CLOSE);
	BIO_set_nbio(io, 1);

	if (ctx) {
		BIO* ssl = BIO_new_ssl(ctx, 0);
		io = BIO_push(ssl, io);
	}

	return spdyC_new(io, true);
}

