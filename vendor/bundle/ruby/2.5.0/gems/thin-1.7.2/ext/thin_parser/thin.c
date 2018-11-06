/**
 * Mongrel Parser adpated to Thin and to play more nicely with Rack specs.
 * 
 * Orignal version Copyright (c) 2005 Zed A. Shaw
 * You can redistribute it and/or modify it under the same terms as Ruby.
 */
#include "ruby.h"
#include "ext_help.h"
#include <assert.h>
#include <string.h>
#include "parser.h"
#include <ctype.h>

static VALUE mThin;
static VALUE cHttpParser;
static VALUE eHttpParserError;

static VALUE global_empty;
static VALUE global_http_prefix;
static VALUE global_request_method;
static VALUE global_request_uri;
static VALUE global_fragment;
static VALUE global_query_string;
static VALUE global_http_version;
static VALUE global_content_length;
static VALUE global_http_content_length;
static VALUE global_request_path;
static VALUE global_content_type;
static VALUE global_http_content_type;
static VALUE global_gateway_interface;
static VALUE global_gateway_interface_value;
static VALUE global_server_name;
static VALUE global_server_port;
static VALUE global_server_protocol;
static VALUE global_server_protocol_value;
static VALUE global_http_host;
static VALUE global_port_80;
static VALUE global_http_body;
static VALUE global_url_scheme;
static VALUE global_url_scheme_value;
static VALUE global_script_name;
static VALUE global_path_info;

#define TRIE_INCREASE 30

/** Defines common length and error messages for input length validation. */
#define DEF_MAX_LENGTH(N,length) const size_t MAX_##N##_LENGTH = length; const char *MAX_##N##_LENGTH_ERR = "HTTP element " # N  " is longer than the " # length " allowed length."

/** Validates the max length of given input and throws an HttpParserError exception if over. */
#define VALIDATE_MAX_LENGTH(len, N) if(len > MAX_##N##_LENGTH) { rb_raise(eHttpParserError, "%s", MAX_##N##_LENGTH_ERR); }

/** Defines global strings in the init method. */
#define DEF_GLOBAL(N, val)   global_##N = rb_obj_freeze(rb_str_new2(val)); rb_global_variable(&global_##N)

/* for compatibility with Ruby 1.8.5, which doesn't declare RSTRING_PTR */
#ifndef RSTRING_PTR
#define RSTRING_PTR(s) (RSTRING(s)->ptr)
#endif

/* for compatibility with Ruby 1.8.5, which doesn't declare RSTRING_LEN */
#ifndef RSTRING_LEN
#define RSTRING_LEN(s) (RSTRING(s)->len)
#endif

/* Defines the maximum allowed lengths for various input elements.*/
DEF_MAX_LENGTH(FIELD_NAME, 256);
DEF_MAX_LENGTH(FIELD_VALUE, 80 * 1024);
DEF_MAX_LENGTH(REQUEST_URI, 1024 * 12);
DEF_MAX_LENGTH(FRAGMENT, 1024); /* Don't know if this length is specified somewhere or not */
DEF_MAX_LENGTH(REQUEST_PATH, 2048);
DEF_MAX_LENGTH(QUERY_STRING, (1024 * 10));
DEF_MAX_LENGTH(HEADER, (1024 * (80 + 32)));

static void http_field(void *data, const char *field, size_t flen, const char *value, size_t vlen)
{
  char *ch, *end;
  VALUE req = (VALUE)data;
  VALUE v = Qnil;
  VALUE f = Qnil;

  VALIDATE_MAX_LENGTH(flen, FIELD_NAME);
  VALIDATE_MAX_LENGTH(vlen, FIELD_VALUE);

  v = rb_str_new(value, vlen);
  f = rb_str_dup(global_http_prefix);
  f = rb_str_buf_cat(f, field, flen); 

  for(ch = RSTRING_PTR(f) + RSTRING_LEN(global_http_prefix), end = RSTRING_PTR(f) + RSTRING_LEN(f); ch < end; ch++) {
    if (*ch >= 'a' && *ch <= 'z') {
      *ch &= ~0x20; // upcase
    } else if (*ch == '-') {
      *ch = '_';
    }
  }

  rb_hash_aset(req, f, v);
}

static void request_method(void *data, const char *at, size_t length)
{
  VALUE req = (VALUE)data;
  VALUE val = Qnil;

  val = rb_str_new(at, length);
  rb_hash_aset(req, global_request_method, val);
}

static void request_uri(void *data, const char *at, size_t length)
{
  VALUE req = (VALUE)data;
  VALUE val = Qnil;

  VALIDATE_MAX_LENGTH(length, REQUEST_URI);

  val = rb_str_new(at, length);
  rb_hash_aset(req, global_request_uri, val);
}

static void fragment(void *data, const char *at, size_t length)
{
  VALUE req = (VALUE)data;
  VALUE val = Qnil;

  VALIDATE_MAX_LENGTH(length, FRAGMENT);

  val = rb_str_new(at, length);
  rb_hash_aset(req, global_fragment, val);
}

static void request_path(void *data, const char *at, size_t length)
{
  VALUE req = (VALUE)data;
  VALUE val = Qnil;

  VALIDATE_MAX_LENGTH(length, REQUEST_PATH);

  val = rb_str_new(at, length);
  rb_hash_aset(req, global_request_path, val);
  rb_hash_aset(req, global_path_info, val);
}

static void query_string(void *data, const char *at, size_t length)
{
  VALUE req = (VALUE)data;
  VALUE val = Qnil;

  VALIDATE_MAX_LENGTH(length, QUERY_STRING);

  val = rb_str_new(at, length);
  rb_hash_aset(req, global_query_string, val);
}

static void http_version(void *data, const char *at, size_t length)
{
  VALUE req = (VALUE)data;
  VALUE val = rb_str_new(at, length);
  rb_hash_aset(req, global_http_version, val);
}

/** Finalizes the request header to have a bunch of stuff that's
  needed. */

static void header_done(void *data, const char *at, size_t length)
{
  VALUE req = (VALUE)data;
  VALUE temp = Qnil;
  VALUE ctype = Qnil;
  VALUE clen = Qnil;
  VALUE body = Qnil;
  char *colon = NULL;

  clen = rb_hash_aref(req, global_http_content_length);
  if(clen != Qnil) {
    rb_hash_aset(req, global_content_length, clen);
    rb_hash_delete(req, global_http_content_length);
  }

  ctype = rb_hash_aref(req, global_http_content_type);
  if(ctype != Qnil) {
    rb_hash_aset(req, global_content_type, ctype);
    rb_hash_delete(req, global_http_content_type);
  }

  rb_hash_aset(req, global_gateway_interface, global_gateway_interface_value);
  if((temp = rb_hash_aref(req, global_http_host)) != Qnil) {
    /* ruby better close strings off with a '\0' dammit */
    colon = strchr(RSTRING_PTR(temp), ':');
    if(colon != NULL) {
      rb_hash_aset(req, global_server_name, rb_str_substr(temp, 0, colon - RSTRING_PTR(temp)));
      rb_hash_aset(req, global_server_port, 
          rb_str_substr(temp, colon - RSTRING_PTR(temp)+1, 
            RSTRING_LEN(temp)));
    } else {
      rb_hash_aset(req, global_server_name, temp);
      rb_hash_aset(req, global_server_port, global_port_80);
    }
  }

  /* grab the initial body and stuff it into the hash */
  if(length > 0) {
    body = rb_hash_aref(req, global_http_body);
    rb_io_write(body, rb_str_new(at, length));
  }
  
  /* according to Rack specs, query string must be empty string if none */
  if (rb_hash_aref(req, global_query_string) == Qnil) {
    rb_hash_aset(req, global_query_string, global_empty);
  }
  if (rb_hash_aref(req, global_path_info) == Qnil) {
    rb_hash_aset(req, global_path_info, global_empty);
  }
  
  /* set some constants */
  rb_hash_aset(req, global_server_protocol, global_server_protocol_value);
  rb_hash_aset(req, global_url_scheme, global_url_scheme_value);
  rb_hash_aset(req, global_script_name, global_empty);
}


void Thin_HttpParser_free(void *data) {
  TRACE();

  if(data) {
    free(data);
  }
}


VALUE Thin_HttpParser_alloc(VALUE klass)
{
  VALUE obj;
  http_parser *hp = ALLOC_N(http_parser, 1);
  TRACE();
  hp->http_field = http_field;
  hp->request_method = request_method;
  hp->request_uri = request_uri;
  hp->fragment = fragment;
  hp->request_path = request_path;
  hp->query_string = query_string;
  hp->http_version = http_version;
  hp->header_done = header_done;
  thin_http_parser_init(hp);

  obj = Data_Wrap_Struct(klass, NULL, Thin_HttpParser_free, hp);

  return obj;
}


/**
 * call-seq:
 *    parser.new -> parser
 *
 * Creates a new parser.
 */
VALUE Thin_HttpParser_init(VALUE self)
{
  http_parser *http = NULL;
  DATA_GET(self, http_parser, http);
  thin_http_parser_init(http);

  return self;
}


/**
 * call-seq:
 *    parser.reset -> nil
 *
 * Resets the parser to it's initial state so that you can reuse it
 * rather than making new ones.
 */
VALUE Thin_HttpParser_reset(VALUE self)
{
  http_parser *http = NULL;
  DATA_GET(self, http_parser, http);
  thin_http_parser_init(http);

  return Qnil;
}


/**
 * call-seq:
 *    parser.finish -> true/false
 *
 * Finishes a parser early which could put in a "good" or bad state.
 * You should call reset after finish it or bad things will happen.
 */
VALUE Thin_HttpParser_finish(VALUE self)
{
  http_parser *http = NULL;
  DATA_GET(self, http_parser, http);
  thin_http_parser_finish(http);

  return thin_http_parser_is_finished(http) ? Qtrue : Qfalse;
}


/**
 * call-seq:
 *    parser.execute(req_hash, data, start) -> Integer
 *
 * Takes a Hash and a String of data, parses the String of data filling in the Hash
 * returning an Integer to indicate how much of the data has been read.  No matter
 * what the return value, you should call HttpParser#finished? and HttpParser#error?
 * to figure out if it's done parsing or there was an error.
 * 
 * This function now throws an exception when there is a parsing error.  This makes 
 * the logic for working with the parser much easier.  You can still test for an 
 * error, but now you need to wrap the parser with an exception handling block.
 *
 * The third argument allows for parsing a partial request and then continuing
 * the parsing from that position.  It needs all of the original data as well 
 * so you have to append to the data buffer as you read.
 */
VALUE Thin_HttpParser_execute(VALUE self, VALUE req_hash, VALUE data, VALUE start)
{
  http_parser *http = NULL;
  int from = 0;
  char *dptr = NULL;
  long dlen = 0;

  DATA_GET(self, http_parser, http);

  from = FIX2INT(start);
  dptr = RSTRING_PTR(data);
  dlen = RSTRING_LEN(data);

  if(from >= dlen) {
    rb_raise(eHttpParserError, "%s", "Requested start is after data buffer end.");
  } else {
    http->data = (void *)req_hash;
    thin_http_parser_execute(http, dptr, dlen, from);

    VALIDATE_MAX_LENGTH(http_parser_nread(http), HEADER);

    if(thin_http_parser_has_error(http)) {
      rb_raise(eHttpParserError, "%s", "Invalid HTTP format, parsing fails.");
    } else {
      return INT2FIX(http_parser_nread(http));
    }
  }
}



/**
 * call-seq:
 *    parser.error? -> true/false
 *
 * Tells you whether the parser is in an error state.
 */
VALUE Thin_HttpParser_has_error(VALUE self)
{
  http_parser *http = NULL;
  DATA_GET(self, http_parser, http);

  return thin_http_parser_has_error(http) ? Qtrue : Qfalse;
}


/**
 * call-seq:
 *    parser.finished? -> true/false
 *
 * Tells you whether the parser is finished or not and in a good state.
 */
VALUE Thin_HttpParser_is_finished(VALUE self)
{
  http_parser *http = NULL;
  DATA_GET(self, http_parser, http);

  return thin_http_parser_is_finished(http) ? Qtrue : Qfalse;
}


/**
 * call-seq:
 *    parser.nread -> Integer
 *
 * Returns the amount of data processed so far during this processing cycle.  It is
 * set to 0 on initialize or reset calls and is incremented each time execute is called.
 */
VALUE Thin_HttpParser_nread(VALUE self)
{
  http_parser *http = NULL;
  DATA_GET(self, http_parser, http);

  return INT2FIX(http->nread);
}

void Init_thin_parser()
{

  mThin = rb_define_module("Thin");

  DEF_GLOBAL(empty, "");
  DEF_GLOBAL(http_prefix, "HTTP_");
  DEF_GLOBAL(request_method, "REQUEST_METHOD");
  DEF_GLOBAL(request_uri, "REQUEST_URI");
  DEF_GLOBAL(fragment, "FRAGMENT");
  DEF_GLOBAL(query_string, "QUERY_STRING");
  DEF_GLOBAL(http_version, "HTTP_VERSION");
  DEF_GLOBAL(request_path, "REQUEST_PATH");
  DEF_GLOBAL(content_length, "CONTENT_LENGTH");
  DEF_GLOBAL(http_content_length, "HTTP_CONTENT_LENGTH");
  DEF_GLOBAL(content_type, "CONTENT_TYPE");
  DEF_GLOBAL(http_content_type, "HTTP_CONTENT_TYPE");
  DEF_GLOBAL(gateway_interface, "GATEWAY_INTERFACE");
  DEF_GLOBAL(gateway_interface_value, "CGI/1.2");
  DEF_GLOBAL(server_name, "SERVER_NAME");
  DEF_GLOBAL(server_port, "SERVER_PORT");
  DEF_GLOBAL(server_protocol, "SERVER_PROTOCOL");
  DEF_GLOBAL(server_protocol_value, "HTTP/1.1");
  DEF_GLOBAL(http_host, "HTTP_HOST");
  DEF_GLOBAL(port_80, "80");
  DEF_GLOBAL(http_body, "rack.input");
  DEF_GLOBAL(url_scheme, "rack.url_scheme");
  DEF_GLOBAL(url_scheme_value, "http");
  DEF_GLOBAL(script_name, "SCRIPT_NAME");
  DEF_GLOBAL(path_info, "PATH_INFO");

  eHttpParserError = rb_define_class_under(mThin, "InvalidRequest", rb_eIOError);

  cHttpParser = rb_define_class_under(mThin, "HttpParser", rb_cObject);
  rb_define_alloc_func(cHttpParser, Thin_HttpParser_alloc);
  rb_define_method(cHttpParser, "initialize", Thin_HttpParser_init,0);
  rb_define_method(cHttpParser, "reset", Thin_HttpParser_reset,0);
  rb_define_method(cHttpParser, "finish", Thin_HttpParser_finish,0);
  rb_define_method(cHttpParser, "execute", Thin_HttpParser_execute,3);
  rb_define_method(cHttpParser, "error?", Thin_HttpParser_has_error,0);
  rb_define_method(cHttpParser, "finished?", Thin_HttpParser_is_finished,0);
  rb_define_method(cHttpParser, "nread", Thin_HttpParser_nread,0);
}
