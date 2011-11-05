/* vim: set noet sts=8 ts=8 sw=8 tw=78: */
#define SPDY_USE_DMEM

#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#ifdef __MACH__
#include <sys/event.h>
#endif

#ifdef __linux__
#include <sys/epoll.h>
#endif

#include <errno.h>
#include <assert.h>

#include <spdy.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#ifdef _WIN32
#define SHUT_WR SD_SEND
#define sleep(t) Sleep((t)*1000)
#else
#define closesocket(s) close(s)
#endif

#include "ssllog.h"

static void basic_auth(d_Vector(char)* v, d_Slice(char) user, d_Slice(char) pass) {
	d_Vector(char) tmp = DV_INIT;
	dv_append(&tmp, user);
	dv_append(&tmp, C(":"));
	dv_append(&tmp, pass);

	dv_set(v, C("Basic "));
	dv_base64_encode(v, tmp);

	dv_free(tmp);
}

static int connect_tcp(d_Slice(char) url) {
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp;
	char *hostname, *port;
	d_Vector(char) urlcopy = DV_INIT;
	int ret = -1;

	if (url.size == 0) {
		return -1;
	}

	dv_set(&urlcopy, url);
	hostname = (char*) urlcopy.data;

	port = strrchr(hostname, ':');
	if (port == NULL) {
		goto end;
	}

	*port = '\0';
	port++;

	/* Strip the square brackets from around the hostname if there are any */
	if (port[-2] == ']' && hostname[0] == '[') {
		hostname++;
		port[-2] = '\0';
	}

	/* Obtain address(es) matching host/port */

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	if (getaddrinfo(hostname, port, &hints, &result) != 0) {
		goto end;
	}

	/* getaddrinfo() returns a list of address structures.
	   Try each address until we successfully connect(2).
	   If socket(2) (or connect(2)) fails, we (close the socket
	   and) try the next address. */

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		int sfd = (int) socket(rp->ai_family,
#ifdef SOCK_CLOEXEC
				rp->ai_socktype | SOCK_CLOEXEC,
#else
				rp->ai_socktype,
#endif
				rp->ai_protocol);

		if (sfd < 0) {
			continue;
		}

#ifndef _WIN32
		fcntl(sfd, F_SETFL, O_NONBLOCK);
		fcntl(sfd, F_SETFD, FD_CLOEXEC);
#endif

		if (connect(sfd, rp->ai_addr, (int) rp->ai_addrlen) &&
#ifdef _WIN32
			WSAGetLastError() == WSAEINPROGRESS
#else
			errno != EINPROGRESS
#endif
			) {
			closesocket(sfd);
			continue;
		}

		ret = sfd;
		break;
	}

end:
	freeaddrinfo(result);
	dv_free(urlcopy);
	return ret;
}

static void register_fd(void* u, int fd);
static void unregister_fd(void* u, int fd);
static void update_send_wait(void* u, int fd, bool enabled);

struct conn {
	int fd;
	spdy_stream* s;
	d_Vector(char) tx; /* to the fd */
	d_Vector(char) rx;
	bool sent_reply;
	bool fd_finished;
	bool s_finished;
	bool send_wait;
};

static int streams;

static void close_conn(struct conn* c) {
	spdyS_send_close(c->s);
	spdyS_deref(c->s);
	unregister_fd(c, c->fd);
	dv_free(c->tx);
	dv_free(c->rx);
	free(c);
	streams--;
}

static int send_reply(struct conn* c) {
	d_Slice(char) d = c->rx;
	spdy_headers* h;
	spdy_reply rep;
	int idx;

	memset(&rep, 0, sizeof(rep));

	idx = dv_find_string(d, C("\n\r\n"));
	if (idx >= 0) {
		idx += 3;
	} else {
		idx = dv_find_string(d, C("\n\n"));

		if (idx >= 0) {
			idx += 2;
		} else if (c->fd_finished) {
			/* Closed before getting the response */
			rep.status = HTTP_BAD_GATEWAY;
			rep.finished = true;
			spdyS_reply(c->s, &rep);
			close_conn(c);
			return -1;
		} else {
			/* More to come to get the response */
			return 1;
		}
	}

	d = dv_left(d, idx);
	h = spdyH_new();

	rep.protocol = dv_split(&d, ' ');
	rep.status = dv_to_integer(dv_split(&d, ' '), 10, HTTP_BAD_GATEWAY);
	rep.status_string = dv_split_line(&d);
	rep.headers = h;

	for (;;) {
		d_Slice(char) line, key, val;
		char* kp;
		int i;

next_header:
		line = dv_split_line(&d);
		if (!line.size) {
			break;
		}

		key = dv_strip_whitespace(dv_split(&line, ':'));
		val = dv_strip_whitespace(line);

		/* lowercase the key - strictly speaking we shouldn't do this
		 * as key is const char, but we know its in a buffer somewhere
		 */

		kp = (char*) key.data;
		kp[key.size] = '\0';
		for (i = 0; i < key.size; i++) {
			if ('A' <= kp[i] && kp[i] <= 'Z') {
				kp[i] += 'a' - 'A';
			} else if (kp[i] == ':' || kp[i] <= ' ' || kp[i] >= 0x7F) {
				goto next_header;
			}
		}

		if (memchr(val.data, '\0', val.size)) {
			goto next_header;
		}

		/* TODO(james): replace with spdyH_add */
		spdyH_set(h, key.data, val);
	}

	if (spdyS_reply(c->s, &rep)) {
		spdyH_free(h);
		close_conn(c);
		return -1;
	}

	spdyH_free(h);
	dv_erase(&c->rx, 0, idx);
	c->sent_reply = true;
	return 0;
}

static void fd_read(void* u);
static void stream_read(void* u, int sts, d_Slice(char) data, int compressed);

static int on_request(void* u, spdy_stream* s, spdy_request* req) {
	struct conn* c;
	int fd;
	int is_connect = dv_equals(req->method, C("CONNECT"));

	if (++streams > 100) {
		return HTTP_SERVICE_UNAVAILABLE;
	}

	fd = connect_tcp(is_connect ? req->host : C("example.com:80"));
	if (fd < 0) {
		return HTTP_BAD_GATEWAY;
	}

	c = (struct conn*) calloc(1, sizeof(struct conn));
	c->fd = fd;
	c->s = s;
	c->send_wait = true;
	spdyS_ref(s);
	register_fd(c, fd);
	spdyS_on_recv(s, &stream_read, c);
	spdyS_on_send_ready(s, &fd_read, c);

	if (is_connect) {
		c->sent_reply = true;
		return HTTP_OK;
	} else {
		int idx;
		const char* key;
		d_Slice(char) vals, val;

		spdyH_set(req->headers, "connection", C("close"));

		/* Format up the HTTP request */
		dv_print(&c->tx, "%.*s %.*s %.*s\r\nHost: %.*s\r\n",
				DV_PRI(req->method),
				DV_PRI(req->path),
				DV_PRI(req->protocol),
				DV_PRI(req->host));

		while (spdyH_next(req->headers, &idx, &key, &vals)) {
			while (vals.size) {
				val = dv_split(&vals, '\0');
				dv_print(&c->tx, "%s: %.*s\r\n", key, DV_PRI(val));
			}
		}

		dv_append(&c->tx, C("\r\n"));
		return 0;
	}
}

static void fd_read(void* u) {
	/* Note we don't grow the buffer larger than this to rate limit the
	 * file descriptor
	 */
	struct conn* c = (struct conn*) u;

	do {
		int r, w;
		dv_reserve(&c->rx, 64 * 1024);

		do {
			r = recv(c->fd, c->rx.data + c->rx.size, dv_reserved(c->rx) - c->rx.size, 0);
		} while (r < 0 && errno == EINTR);

		if (r < 0 && errno == EAGAIN) {
			r = 0;
		} else if (r == 0) {
			c->fd_finished = true;
		} else if (r < 0) {
			goto err;
		}

		dv_resize(&c->rx, c->rx.size + r);

		if (!c->sent_reply && send_reply(c)) {
			return;
		}

		w = spdyS_send(c->s, c->rx, 0);
		if (w < 0) {
			goto err;
		}

		dv_erase(&c->rx, 0, w);

		if (c->fd_finished && !c->rx.size) {
			if (spdyS_send_close(c->s)) {
				goto err;
			}
		}

		if (c->fd_finished && c->s_finished) {
			close_conn(c);
			return;
		}

	} while (!c->fd_finished && !c->rx.size);

	return;
err:
	close_conn(c);
}

static void fd_write(void* u) {
	struct conn* c = (struct conn*) u;
	if (c->tx.size) {
		int w;

		do {
			w = send(c->fd, c->tx.data, c->tx.size, 0);
		} while (w < 0 && errno == EINTR);

		if (w <= 0 && errno == EAGAIN) {
			w = 0;
		} else if (w <= 0) {
			goto err;
		}

		dv_erase(&c->tx, 0, w);

		if (spdyS_recv_ready(c->s, w)) {
			goto err;
		}

		if (c->s_finished && !c->tx.size) {
			shutdown(c->fd, SHUT_WR);
		}
	}

	if ((c->tx.size != 0) != c->send_wait) {
		c->send_wait = !c->send_wait;
		update_send_wait(c, c->fd, c->send_wait);
	}

	return;

err:
	close_conn(c);
}

static void stream_read(void* u, int sts, d_Slice(char) data, int compressed) {
	struct conn* c = (struct conn*) u;

	if (sts < 0 || compressed) {
		goto err;
	}

	if (sts == SPDY_FINISHED) {
		c->s_finished = true;
	}

	if (c->fd_finished && c->s_finished) {
		close_conn(c);
		return;
	}

	if (c->tx.size) {
		int w;

		do {
			w = send(c->fd, c->tx.data, c->tx.size, 0);
		} while (w < 0 && errno == EINTR);

		if (w <= 0 && errno == EAGAIN) {
			w = 0;
		} else if (w <= 0) {
			goto err;
		}

		dv_erase(&c->tx, 0, w);

		if (spdyS_recv_ready(c->s, w)) {
			goto err;
		}
	}

	if (!c->tx.size && data.size) {
		int w;

		do {
			w = send(c->fd, data.data, data.size, 0);
		} while (w < 0 && errno == EINTR);

		if (w <= 0 && errno == EAGAIN) {
			w = 0;
		} else if (w < 0) {
			goto err;
		}

		data = dv_right(data, w);

		if (spdyS_recv_ready(c->s, w)) {
			goto err;
		}
	}

	dv_append(&c->tx, data);

	if (c->s_finished && !c->tx.size) {
		shutdown(c->fd, SHUT_WR);
	}

	if ((c->tx.size != 0) != c->send_wait) {
		c->send_wait = !c->send_wait;
		update_send_wait(c, c->fd, c->send_wait);
	}

	return;

err:
	close_conn(c);
}

static void on_timeout(void);
#define POLL_TIMEOUT 20

#ifdef __MACH__
DVECTOR_INIT(kevent, struct kevent);
static d_Vector(kevent) changes;
static d_Vector(kevent) events;

static void register_fd(void* u, int fd) {
	struct kevent* e = dv_append_buffer(&changes, 2);

	e[0].ident = fd;
	e[0].filter = EVFILT_READ;
	e[0].flags = EV_ADD;
	e[0].fflags = 0;
	e[0].udata = u;

	e[1].ident = fd;
	e[1].filter = EVFILT_WRITE;
	e[1].flags = EV_ADD;
	e[1].fflags = 0;
	e[1].udata = u;
}

static void unregister_fd(void* u, int fd) {
	int i;
	streams--;
	close(fd);

	for (i = 0; i < events.size; i++) {
		if (u == events.data[i].udata) {
			events.data[i].udata = NULL;
		}
	}
}

static void update_send_wait(void* u, int fd, bool enabled) {
	struct kevent* e = dv_append_buffer(&changes, 1);
	e->ident = fd;
	e->filter = EVFILT_WRITE;
	e->flags = enabled ? EV_ENABLE : EV_DISABLE;
	e->fflags = 0;
	e->udata = u;
}

static void main_loop(spdy_connection* client, int* die) {
	int kq = kqueue();
	struct timespec ts;
	ts.tv_sec = POLL_TIMEOUT;
	ts.tv_nsec = 0;

	while (!*die) {
		int i, ret;

		dv_reserve(&events, 64);
		ret = kevent(kq, changes.data, changes.size, events.data, 64, &ts);

		if (ret < 0 && errno == EINTR) {
			continue;
		} else if (ret < 0) {
			exit(-1);
		}

		if (ret == 0) {
			on_timeout();
		}

		dv_clear(&changes);
		dv_resize(&events, ret);

		for (i = 0; i < events.size; i++) {
			struct kevent* e = &events.data[i];

			if (e->udata == client) {

				if (e->filter == EVFILT_READ) {
					if (spdyC_recv_ready(client)) {
						return;
					}

				} else if (e->filter == EVFILT_WRITE) {
					if (spdyC_send_ready(client)) {
						return;
					}
				}

			} else if (e->udata) {

				if (e->filter == EVFILT_READ) {
					fd_read(e->udata);
				} else if (e->filter == EVFILT_WRITE) {
					fd_write(e->udata);
				}

			}
		}
	}
}

#elif defined __linux__
DVECTOR_INIT(epoll_event, struct epoll_event);
static d_Vector(epoll_event) events;
static int epfd;
#define POLL_READ (EPOLLIN | EPOLLHUP | EPOLLERR)

static void register_fd(void* u, int fd) {
	struct epoll_event e;
	e.events = POLL_READ | EPOLLOUT;
	e.data.ptr = u;
	epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &e);
}

static void unregister_fd(void* u, int fd) {
	int i;
	close(fd);

	for (i = 0; i < events.size; i++) {
		if (u == events.data[i].data.ptr) {
			events.data[i].data.ptr = NULL;
		}
	}
}

static void update_send_wait(void* u, int fd, bool enabled) {
	struct epoll_event e;
	if (enabled) {
		e.events = POLL_READ | EPOLLOUT;
	} else {
		e.events = POLL_READ;
	}
	e.data.ptr = u;
	epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &e);
}

static void main_loop(spdy_connection* client, int* die) {
	while (!*die) {
		int i, ret;

		dv_reserve(&events, 64);
		ret = epoll_wait(epfd, events.data, 64, POLL_TIMEOUT * 1000);

		if (ret < 0 && errno == EINTR) {
			continue;
		} else if (ret < 0) {
			exit(-1);
		}

		if (ret == 0) {
			on_timeout();
			continue;
		}

		dv_resize(&events, ret);

		for (i = 0; i < events.size; i++) {
			struct epoll_event* e = &events.data[i];

			if (e->data.ptr == client) {
				if (e->data.ptr && (e->events & POLL_READ)) {
					if (spdyC_recv_ready(client)) {
						return;
					}
				}

				if (e->data.ptr && (e->events & EPOLLOUT)) {
					if (spdyC_send_ready(client)) {
						return;
					}
				}
			} else {

				if (e->data.ptr && (e->events & POLL_READ)) {
					fd_read(e->data.ptr);
				}

				if (e->data.ptr && (e->events & EPOLLOUT)) {
					fd_write(e->data.ptr);
				}
			}
		}
	}
}

#elif defined _WIN32
#define POLL_READ (FD_READ | FD_CLOSE | FD_ACCEPT)
#define POLL_WRITE (FD_WRITE | FD_CONNECT)
struct reg {
	void* ptr;
	SOCKET fd;
};
DVECTOR_INIT(event, HANDLE);
DVECTOR_INIT(reg, struct reg);
static d_Vector(event) events;
static d_Vector(reg) regs;
static void* current_data;

static void register_fd(void* u, int fd) {
	struct reg* r;
	HANDLE e = WSACreateEvent();
	WSAEventSelect(fd, e, POLL_READ | POLL_WRITE);
	dv_append1(&events, e);
	r = dv_append_buffer(&regs, 1);
	r->ptr = u;
	r->fd = (SOCKET) fd;
}

static void unregister_fd(void* u, int fd) {
	int i;
	if (u == current_data) {
		current_data = NULL;
	}

	for (i = 0; i < regs.size; i++) {
		if (regs.data[i].ptr == u) {
			CloseHandle(events.data[i]);
			closesocket(regs.data[i].fd);
			break;
		}
	}

}

static void update_send_wait(void* u, int fd, bool enabled) {
	int i;
	for (i = 0; i < regs.size; i++) {
		if (regs.data[i].ptr == u) {
			WSAEventSelect(fd, events.data[i], POLL_READ | (enabled ? POLL_WRITE : 0));
			break;
		}
	}
}

static void main_loop(spdy_connection* client, int* die) {
	while (!*die) {
		struct reg* r;
		WSANETWORKEVENTS ev;
		int i = (int) WaitForMultipleObjects(events.size, events.data, FALSE, POLL_TIMEOUT * 1000);

		if (i == 0) {
			on_timeout();
			continue;
		} else if (i < 0 || i > events.size) {
			return;
		}

		r = &regs.data[i];

		if (WSAEnumNetworkEvents(r->fd, events.data[i], &ev)) {
			continue;
		}

		current_data = r->ptr;

		if (current_data == client) {
			if (ev.lNetworkEvents & POLL_READ) {
				spdyC_recv_ready(client);
			}
			if (current_data && (ev.lNetworkEvents & POLL_WRITE)) {
				spdyC_send_ready(client);
			}
		} else {
			if (ev.lNetworkEvents & POLL_READ) {
				fd_read(current_data);
			}
			if (current_data && (ev.lNetworkEvents & POLL_WRITE)) {
				fd_write(current_data);
			}
		}
	}
}
#endif

static int clientfd;
static int retry_timeout = 1000;
static int die;

static void client_send_ready(void* u, int enabled) {
	update_send_wait(u, clientfd, enabled != 0);
}

static void bind_reply(void* u, spdy_reply* r) {
	if (r->status == HTTP_OK) {
		retry_timeout = 500;
	} else {
		die = 1;
	}
}

static void bind_recv(void* u, int sts, d_Slice(char) data, int compressed) {
	if (!sts) {
		return;
	}

	die = 1;

	retry_timeout *= 2;
	if (retry_timeout > 300000) {
		retry_timeout = 300000;
	}
}

static spdy_stream* cstream;

static void on_timeout(void) {
	if (spdyS_send(cstream, C(" "), 0) < 0) {
		die = 1;
	}
}

int main(int argc, char* argv[]) {
	SSL_CTX *ctx;

#if defined __linux__ && defined EPOLL_CLOEXEC
	epfd = epoll_create1(EPOLL_CLOEXEC);
#elif defined __linux__
	epfd = epoll_create(0);
	fcntl(epfd, F_SETFD, FD_CLOEXEC);

#elif defined _WIN32
	WSADATA wsadata;
	WSAStartup(MAKEWORD(2,2), &wsadata);
#endif

	if (argc < 5) {
		fprintf(stderr, "usage: client server hostname username password\n");
		return -2;
	}

	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	ctx = SSL_CTX_new(TLSv1_client_method());

	/*SSL_CTX_set_msg_callback(ctx, &SSL_MsgCallback);*/

	for (;;) {
		spdy_connection* client = spdyC_connect(argv[1], ctx, &clientfd);

		if (client) {
			spdy_request r;
			spdy_headers* h = spdyH_new();
			d_Vector(char) auth = DV_INIT;
			d_Vector(char) path = DV_INIT;

			/* Setup the client */
			spdyC_on_send_wait(client, &client_send_ready, client);
			register_fd(client, clientfd);

			/* Setup the request */
			basic_auth(&auth, dv_char(argv[3]), dv_char(argv[4]));
			spdyH_set(h, "authorization", auth);

			dv_set(&path, C("/bind?hostname="));
			dv_url_encode(&path, dv_char(argv[2]));

			memset(&r, 0, sizeof(r));
			r.host = dv_char(argv[1]);
			r.path = path;
			r.headers = h;

			/* Setup the stream */
			cstream = spdyS_new();
			spdyS_ref(cstream);
			spdyS_on_recv(cstream, &bind_recv, NULL);
			spdyS_on_reply(cstream, &bind_reply, NULL);
			spdyS_on_request(cstream, &on_request, NULL);

			/* Send the request and wait for it to end */
			die = 0;
			spdyC_start(client, cstream, &r);
			main_loop(client, &die);

			/* Cleanup */
			spdyH_free(h);
			dv_free(auth);
			dv_free(path);
			spdyC_free(client);
			spdyS_deref(cstream);
		} else {
			retry_timeout *= 2;
		}

		if (retry_timeout > 300000) {
			retry_timeout = 300000;
			sleep(300);
		} else {
			sleep(retry_timeout / 1000);
		}

	}

	return 0;
}

