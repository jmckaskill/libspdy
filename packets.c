/* vim: set noet sts=8 ts=8 sw=8 tw=78: */
#define SPDY_USE_DMEM
#include "packets.h"
#include <dmem/zlib.h>
#include <assert.h>

#define FLAG_LENGTH             UINT32_C(0x00FFFFFF)
#define FLAG_FINISHED           UINT32_C(0x01000000)
#define FLAG_UNIDIRECTIONAL     UINT32_C(0x02000000)
#define FLAG_COMPRESSED         UINT32_C(0x02000000)

#define PRIORITY_SHIFT          5

spdy_headers* spdyH_new(void) {
	return (spdy_headers*) calloc(1, sizeof(spdy_headers));
}

void spdyH_free(spdy_headers* h) {
	if (h) {
		dh_free(&h->h);
		dv_free(h->v);
	}
}

static int next_header(spdy_headers* h, int* idx, d_Slice(char)* key, d_Slice(char)* val) {
	if (!dh_hasnext(&h->h, idx)) {
		return 0;
	}

	key->data = (uintptr_t) h->h.keys[*idx].data + h->v.data;
	key->size = h->h.vals[*idx].size;
	val->data = (uintptr_t) h->h.vals[*idx].data + h->v.data;
	val->size = h->h.vals[*idx].size;

	return 1;
}

int spdyH_next(spdy_headers* h, int* idx, const char** key, spdy_string* val) {
	d_Slice(char) ks;
	if (!next_header(h, idx, &ks, val)) {
		return 0;
	}
	*key = ks.data;
	return 1;
}

spdy_string spdyH_get(spdy_headers* h, const char* key) {
	d_Slice(char) ret = DV_INIT;
	if (!dhs_get(&h->h, dv_char(key), &ret)) {
		return ret;
	}

	ret.data += (uintptr_t) h->v.data;
	return dv_split_left(&ret, '\0');
}

void spdyH_del(spdy_headers* h, const char* key) {
	dhs_remove(&h->h, dv_char(key));
}

void spdyH_add(spdy_headers* h, const char* key, spdy_string val) {
	int vi;
	d_Slice(char) hdr;

	if (dhs_add(&h->h, dv_char(key), &vi)) {
		dv_append(&h->v, val);
		dv_append1(&h->v, '\0');
		h->h.vals[vi].data = (void*) (uintptr_t) (h->v.size - val.size);
		h->h.vals[vi].size = val.size;
		return;
	}

	// Append to an already added header
	hdr = h->h.vals[vi];

	// We need to copy the existing header to the end if its not already
	// at the end
	if ((uintptr_t) hdr.data + hdr.size != h->v.size + 1) {
		dv_append(&h->v, hdr);
		h->h.vals[vi].data = (void*) (uintptr_t) (h->v.size - hdr.size);
	}

	dv_append(&h->v, val);
	h->h.vals[vi].size += val.size + 1;
	return;
}

/* returns 1 if the header was added */
static int add_full_header(spdy_headers* h, d_Slice(char) key, d_Slice(char) val) {
	int vi;
	int ret = 1;

	if (!dhs_add(&h->h, key, &vi)) {
		d_Slice(char) hdr = h->h.vals[vi];

		// The existing header is at the end of the buffer
		if ((uintptr_t) hdr.data + hdr.size == h->v.size + 1) {
			dv_erase_end(&h->v, hdr.size + 1);
		}

		ret = 0;
	}

	dv_append(&h->v, val);
	dv_append1(&h->v, '\0');
	h->h.vals[vi].data = (void*) (uintptr_t) (h->v.size - val.size);
	h->h.vals[vi].size = val.size;
	return ret;
}

void spdyH_set(spdy_headers* h, const char* key, spdy_string val) {
	add_full_header(h, dv_char(key), val);
}


static void w32(char* p, uint32_t v) {
	p[0] = (uint8_t) (v >> 24);
	p[1] = (uint8_t) (v >> 16);
	p[2] = (uint8_t) (v >> 8);
	p[3] = (uint8_t) (v);
}

static uint32_t r32(char* p) {
	return ((uint32_t) p[0] << 24) |
		((uint32_t) p[1] << 16) |
		((uint32_t) p[2] << 8) |
		((uint32_t) p[3]);
}

#define control_common \
	char type[4]; \
	char flags[4]

struct control_hdr {
	control_common;
};

void parse_frame(uint32_t* type, int* length, const char* data) {
	struct control_hdr* h = (struct control_hdr*) data;

	*type = r32(h->type);
	*length = (int) (r32(h->flags) & FLAG_LENGTH) + FRAME_HEADER_SIZE;
}

struct data_hdr {
	char stream[4];
	char flags[4];
};

void marshal_data_header(char* out, struct data* s) {
	struct data_hdr* h = (struct data_hdr*) out;
	w32(h->stream, s->stream);
	w32(h->flags, s->size | (s->finished ? FLAG_FINISHED : 0) | (s->compressed ? FLAG_COMPRESSED : 0));
}

void parse_data(struct data* s, d_Slice(char) d) {
	assert(d.size >= DATA_HEADER_SIZE);
	struct data_hdr* h = (struct data_hdr*) d.data;
	s->stream = (int) r32(h->stream);

	uint32_t flags = r32(h->flags);
	s->finished = (flags & FLAG_FINISHED) != 0;
	s->compressed = (flags & FLAG_COMPRESSED) != 0;
}

static void deflate_v3(d_Vector(char)* out, z_stream* z, d_Slice(char) key, d_Slice(char) val) {
	uint32_t klen = (uint32_t) htonl(key.size);
	uint32_t vlen = (uint32_t) htonl(val.size);
#ifndef NDEBUG
	{
		int i;
		for (i = 0; i < key.size; i++) {
			assert(key.data[i] < 'A' || key.data[i] > 'Z');
		}
	}
#endif

	dz_deflate(out, z, dv_char2((char*) &klen, 4), Z_NO_FLUSH);
	dz_deflate(out, z, dv_char2((char*) &vlen, 4), Z_NO_FLUSH);
	dz_deflate(out, z, key, Z_NO_FLUSH);
	dz_deflate(out, z, val, Z_NO_FLUSH);
}

static void begin_deflate_v3(d_Vector(char)* out, z_stream* z, spdy_headers* hdrs, int extra) {
	uint32_t numvals = (uint32_t) htonl((hdrs ? dh_size(&hdrs->h) : 0) + extra);
	dz_deflate(out, z, dv_char2((char*) &numvals, 4), Z_NO_FLUSH);

	if (hdrs) {
		int idx = -1;
		d_Slice(char) key, val;
		while (next_header(hdrs, &idx, &key, &val)) {
			deflate_v3(out, z, key, val);
		}
	}
}

struct extra_headers {
	d_Slice(char) status;
	d_Slice(char) version;
	d_Slice(char) method;
	d_Slice(char) scheme;
	d_Slice(char) host;
	d_Slice(char) path;
};

static int inflate_v3(spdy_headers* hdrs, struct extra_headers* e, z_stream* z, d_Slice(char) d, d_Vector(char)* buf) {
	int i, err, vals;

	dv_clear(&hdrs->v);
	dh_clear(&hdrs->h);

	err = dz_inflate(buf, z, d);
	if (err) return err;

	d = *buf;
	if (d.size < 4) {
		return SPDY_PROTOCOL;
	}
	vals = (int) r32(d.data);
	if (vals < 0) {
		return SPDY_PROTOCOL;
	}
	d = dv_right(d, 4);

	for (i = 0; i < vals; i++) {
		int klen, vlen, j;
		d_Slice(char) key, val;

		if (d.size < 4) {
			return SPDY_PROTOCOL;
		}

		klen = (int) r32(d.data);
		d = dv_right(d, 4);

		if (d.size < klen + 4 || klen < 0) {
			return SPDY_PROTOCOL;
		}

		key = dv_left(d, klen);
		d = dv_right(d, klen);

		vlen = (int) r32(d.data);
		d = dv_right(d, 4);

		if (d.size < vlen || vlen < 0) {
			return SPDY_PROTOCOL;
		}

		val = dv_left(d, vlen);
		d = dv_right(d, vlen);

		// From RFC822, headers are allowed to have any ASCII
		// character except CTLs, SPACE, and ':'.  The spdy spec
		// further restricts this to only upper case and allowing : as
		// the first character.
		for (j = 0; j < key.size; j++) {
			if (key.data[j] <= ' ' /* space, ctls and 8 bit for signed char */
					|| key.data[j] >= 0x7F /* delete and 8 bit for unsigned char */
					|| (key.data[j] == ':' && j != 0)) {
				return SPDY_PROTOCOL;
			}
		}

		if (key.size == 0) {
			continue;
		}

		if (key.data[j] == ':') {
			if (dv_equals(key, C(":status"))) {
				e->status = val;
			} else if (dv_equals(key, C(":version"))) {
				e->version = val;
			} else if (dv_equals(key, C(":method"))) {
				e->method = val;
			} else if (dv_equals(key, C(":scheme"))) {
				e->scheme = val;
			} else if (dv_equals(key, C(":host"))) {
				e->host = val;
			} else if (dv_equals(key, C(":path"))) {
				e->path = val;
			}
			// Ignore other internal headers that we don't
			// understand
		} else {
			// Headers must be unique
			if (!add_full_header(hdrs, key, val)) {
				return SPDY_PROTOCOL;
			}
		}
	}

	return 0;
}

struct syn_stream_hdr {
	control_common;
	char stream[4];
	char associated_stream[4];
	uint8_t priority;
	uint8_t unused;
};

void marshal_syn_stream(d_Vector(char)* out, struct syn_stream* s, z_stream* z) {
	int begin = out->size;
	dv_append_buffer(out, sizeof(struct syn_stream_hdr));

	if (s->path.size == 0) {
		s->path = C("/");
	}

	begin_deflate_v3(out, z, s->headers, 5);
	deflate_v3(out, z, C(":version"), s->protocol);
	deflate_v3(out, z, C(":method"), s->method);
	deflate_v3(out, z, C(":path"), s->path);
	deflate_v3(out, z, C(":host"), s->host);
	deflate_v3(out, z, C(":scheme"), s->scheme);
	dz_deflate(out, z, C(""), Z_SYNC_FLUSH);

	struct syn_stream_hdr* h = (struct syn_stream_hdr*) &out->data[begin];

	uint32_t flags = (out->size - begin) |
	       	(s->finished ? FLAG_FINISHED : 0) |
	       	(s->unidirectional ? FLAG_UNIDIRECTIONAL : 0);

	w32(h->type, SYN_STREAM);
	w32(h->flags, flags);
	w32(h->stream, s->stream);
	w32(h->associated_stream, s->associated_stream);
	h->priority = s->priority << PRIORITY_SHIFT;
	h->unused = 0;
}

int parse_syn_stream(struct syn_stream* s, d_Slice(char) d, z_stream* z, d_Vector(char)* buf) {
	if (d.size < sizeof(struct syn_stream_hdr)) {
		return SPDY_PROTOCOL;
	}

	struct syn_stream_hdr* h = (struct syn_stream_hdr*) d.data;
	uint32_t flags = r32(h->flags);

	s->finished = (flags & FLAG_FINISHED) != 0;
	s->unidirectional = (flags & FLAG_UNIDIRECTIONAL) != 0;
	s->stream = (int) r32(h->stream);
	s->associated_stream = (int) r32(h->associated_stream);
	s->priority = (int) (h->priority >> PRIORITY_SHIFT);

	if (s->stream < 0 || s->associated_stream < 0) {
		return SPDY_PROTOCOL;
	}

	struct extra_headers e;
	memset(&e, 0, sizeof(e));

	int err = inflate_v3(s->headers, &e, z, dv_right(d, sizeof(struct syn_stream_hdr)), buf);
	if (err) return err;

	if (!e.version.size || !e.method.size || !e.scheme.size || !e.host.size || !e.path.size) {
		return SPDY_PROTOCOL;
	}

	s->protocol = e.version;
	s->method = e.method;
	s->scheme = e.scheme;
	s->host = e.host;
	s->path = e.path;

	return 0;
}

struct syn_reply_hdr {
	control_common;
	char stream[4];
};

void marshal_syn_reply(d_Vector(char)* out, struct syn_reply* s, z_stream* z) {
	int begin = out->size;
	dv_append_buffer(out, sizeof(struct syn_reply_hdr));

	begin_deflate_v3(out, z, s->headers, 2);
	deflate_v3(out, z, C(":status"), s->status);
	deflate_v3(out, z, C(":version"), s->protocol);
	dz_deflate(out, z, C(""), Z_SYNC_FLUSH);

	struct syn_reply_hdr* h = (struct syn_reply_hdr*) &out->data[begin];

	w32(h->type, SYN_REPLY);
	w32(h->flags, (out->size - begin) | (s->finished ? FLAG_FINISHED : 0));
	w32(h->stream, s->stream);
}

int parse_syn_reply(struct syn_reply* s, d_Slice(char) d, z_stream* z, d_Vector(char)* buf) {
	if (d.size < sizeof(struct syn_reply_hdr)) {
		return SPDY_PROTOCOL;
	}

	struct syn_reply_hdr* h = (struct syn_reply_hdr*) d.data;

	s->finished = (r32(h->flags) & FLAG_FINISHED) != 0;
	s->stream = (int) r32(h->stream);

	struct extra_headers e;
	memset(&e, 0, sizeof(e));

	int err = inflate_v3(s->headers, &e, z, dv_right(d, sizeof(struct syn_reply_hdr)), buf);
	if (err) return err;

	if (!e.status.size || !e.version.size) {
		return SPDY_PROTOCOL;
	}

	s->status = e.status;
	s->protocol = e.version;

	return 0;
}

struct rst_stream_hdr {
	control_common;
	char stream[4];
	char error[4];
};

void marshal_rst_stream(d_Vector(char)* out, int stream, int error) {
	struct rst_stream_hdr* h = (struct rst_stream_hdr*) dv_append_buffer(out, sizeof(struct rst_stream_hdr));

	w32(h->type, RST_STREAM);
	w32(h->flags, sizeof(struct rst_stream_hdr));
	w32(h->stream, stream);
	w32(h->error, -error);
}

int parse_rst_stream(int* stream, int* error, d_Slice(char) d) {
	if (d.size < sizeof(struct rst_stream_hdr)) {
		return SPDY_PROTOCOL;
	}

	struct rst_stream_hdr* h = (struct rst_stream_hdr*) d.data;

	*stream = (int) r32(h->stream);
	*error = -(int) r32(h->error);

	// Filter out errors that would collide with API errors
	if (*error <= SPDY_GO_AWAY || *error >= 0) {
		*error = SPDY_PROTOCOL;
	}

	return 0;
}

struct settings_hdr {
	control_common;
};

struct ping_hdr {
	control_common;
	char id[4];
};

void marshal_ping(d_Vector(char)* out, uint32_t id) {
	struct ping_hdr* h = (struct ping_hdr*) dv_append_buffer(out, sizeof(struct ping_hdr));

	w32(h->type, PING);
	w32(h->flags, sizeof(struct ping_hdr));
	w32(h->id, id);
}

int parse_ping(uint32_t* id, d_Slice(char) d) {
	if (d.size < sizeof(struct ping_hdr)) {
		return SPDY_PROTOCOL;
	}
	*id = r32(((struct ping_hdr*) d.data)->id);
	return 0;
}

struct goaway_hdr {
	control_common;
	char last_stream[4];
	char error[4];
};

struct headers_hdr {
	control_common;
};

struct window_hdr {
	control_common;
	char stream[4];
	char window_delta[4];
};

void marshal_window(d_Vector(char)* out, int stream, int delta) {
	struct window_hdr* h = (struct window_hdr*) dv_append_buffer(out, sizeof(struct window_hdr));

	w32(h->type, WINDOW_UPDATE);
	w32(h->flags, sizeof(struct window_hdr));
	w32(h->stream, stream);
	w32(h->window_delta, delta);
}

int parse_window(int* stream, int* delta, d_Slice(char) d) {
	if (d.size < sizeof(struct window_hdr)) {
		return SPDY_PROTOCOL;
	}

	struct window_hdr* h = (struct window_hdr*) d.data;

	*stream = (int) r32(h->stream);
	*delta = (int) r32(h->window_delta);
	return 0;
}

