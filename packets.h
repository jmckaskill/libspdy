/* vim: set noet sts=8 ts=8 sw=8 tw=78: */
#pragma once

#include <spdy.h>
#include <dmem/char.h>
#include <dmem/hash.h>
#include <zlib.h>

#define DEFAULT_WINDOW (64 * 1024)
#define FRAME_HEADER_SIZE 8
#define DATA_HEADER_SIZE 8
#define DEFAULT_PRIORITY 4
#define NUM_PRIORITIES 8
#define MAX_STREAM_ID INT32_C(0x0FFFFFFE)

#define SYN_STREAM              UINT32_C(0x80030001)
#define SYN_REPLY               UINT32_C(0x80030002)
#define RST_STREAM              UINT32_C(0x80030003)
#define SETTINGS                UINT32_C(0x80030004)
#define NOOP                    UINT32_C(0x80030005)
#define PING                    UINT32_C(0x80030006)
#define GO_AWAY                 UINT32_C(0x80030007)
#define HEADERS                 UINT32_C(0x80030008)
#define WINDOW_UPDATE           UINT32_C(0x80030009)

#define FLAG_CONTROL            UINT32_C(0x80000000)

DHASH_INIT_STR(hdr, d_Slice(char));

struct spdy_headers {
	d_StringHash(hdr) h;
	d_Vector(char) v;
};

void parse_frame(uint32_t* type, int* length, const char* data);

struct data {
	bool finished;
	bool compressed;
	int stream;
	int size;
};

void marshal_data_header(char* out, struct data* s);
void parse_data(struct data* s, d_Slice(char) d);

struct syn_stream {
	bool finished;
	bool unidirectional;
	int stream;
	int associated_stream;
	spdy_headers* headers;
	int priority;
	d_Slice(char) scheme;
	d_Slice(char) host;
	d_Slice(char) path;
	d_Slice(char) protocol;
	d_Slice(char) method;
};

void marshal_syn_stream(d_Vector(char)* out, struct syn_stream* s, z_stream* z);
int parse_syn_stream(struct syn_stream* s, d_Slice(char) d, z_stream* z, d_Vector(char)* buf);

struct syn_reply {
	bool finished;
	int stream;
	spdy_headers* headers;
	d_Slice(char) status;
	d_Slice(char) protocol;
};

void marshal_syn_reply(d_Vector(char)* out, struct syn_reply* s, z_stream* z);
int parse_syn_reply(struct syn_reply* s, d_Slice(char) d, z_stream* z, d_Vector(char)* buf);

void marshal_rst_stream(d_Vector(char)* out, int stream, int error);
int parse_rst_stream(int* stream, int* error, d_Slice(char) d);

void marshal_ping(d_Vector(char)* out, uint32_t id);
int parse_ping(uint32_t* id, d_Slice(char) d);

void marshal_window(d_Vector(char)* out, int stream, int delta);
int parse_window(int* stream, int* delta, d_Slice(char) d);
