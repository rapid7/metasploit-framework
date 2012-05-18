
#line 1 "parser.rl"
/**
 * Copyright (c) 2005 Zed A. Shaw
 * You can redistribute it and/or modify it under the same terms as Ruby.
 */
#include "parser.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define LEN(AT, FPC) (FPC - buffer - parser->AT)
#define MARK(M,FPC) (parser->M = (FPC) - buffer)
#define PTR_TO(F) (buffer + parser->F)

/** Machine **/


#line 81 "parser.rl"


/** Data **/

#line 27 "parser.c"
static const int http_parser_start = 1;
static const int http_parser_first_final = 58;
static const int http_parser_error = 0;

static const int http_parser_en_main = 1;


#line 85 "parser.rl"

int thin_http_parser_init(http_parser *parser)  {
  int cs = 0;
  
#line 40 "parser.c"
	{
	cs = http_parser_start;
	}

#line 89 "parser.rl"
  parser->cs = cs;
  parser->body_start = 0;
  parser->content_len = 0;
  parser->mark = 0;
  parser->nread = 0;
  parser->field_len = 0;
  parser->field_start = 0;    

  return(1);
}


/** exec **/
size_t thin_http_parser_execute(http_parser *parser, const char *buffer, size_t len, size_t off)  {
  const char *p, *pe;
  int cs = parser->cs;

  assert(off <= len && "offset past end of buffer");

  p = buffer+off;
  pe = buffer+len;

  assert(*pe == '\0' && "pointer does not end on NUL");
  assert(pe - p == len - off && "pointers aren't same distance");


  
#line 73 "parser.c"
	{
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	switch( (*p) ) {
		case 36: goto tr0;
		case 95: goto tr0;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr0;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto tr0;
	} else
		goto tr0;
	goto st0;
st0:
cs = 0;
	goto _out;
tr0:
#line 22 "parser.rl"
	{MARK(mark, p); }
	goto st2;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
#line 104 "parser.c"
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st39;
		case 95: goto st39;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st39;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st39;
	} else
		goto st39;
	goto st0;
tr2:
#line 36 "parser.rl"
	{ 
    if (parser->request_method != NULL) {
      parser->request_method(parser->data, PTR_TO(mark), LEN(mark, p));
    }
  }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 131 "parser.c"
	switch( (*p) ) {
		case 42: goto tr4;
		case 43: goto tr5;
		case 47: goto tr6;
		case 58: goto tr7;
	}
	if ( (*p) < 65 ) {
		if ( 45 <= (*p) && (*p) <= 57 )
			goto tr5;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr5;
	} else
		goto tr5;
	goto st0;
tr4:
#line 22 "parser.rl"
	{MARK(mark, p); }
	goto st4;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
#line 155 "parser.c"
	switch( (*p) ) {
		case 32: goto tr8;
		case 35: goto tr9;
	}
	goto st0;
tr8:
#line 41 "parser.rl"
	{
    if (parser->request_uri != NULL) {
      parser->request_uri(parser->data, PTR_TO(mark), LEN(mark, p));
    }
  }
	goto st5;
tr31:
#line 22 "parser.rl"
	{MARK(mark, p); }
#line 46 "parser.rl"
	{ 
    if (parser->fragment != NULL) {
      parser->fragment(parser->data, PTR_TO(mark), LEN(mark, p));
    }
  }
	goto st5;
tr34:
#line 46 "parser.rl"
	{ 
    if (parser->fragment != NULL) {
      parser->fragment(parser->data, PTR_TO(mark), LEN(mark, p));
    }
  }
	goto st5;
tr44:
#line 65 "parser.rl"
	{
    if (parser->request_path != NULL) {
      parser->request_path(parser->data, PTR_TO(mark), LEN(mark,p));
    }
  }
#line 41 "parser.rl"
	{
    if (parser->request_uri != NULL) {
      parser->request_uri(parser->data, PTR_TO(mark), LEN(mark, p));
    }
  }
	goto st5;
tr51:
#line 52 "parser.rl"
	{MARK(query_start, p); }
#line 53 "parser.rl"
	{ 
    if (parser->query_string != NULL) {
      parser->query_string(parser->data, PTR_TO(query_start), LEN(query_start, p));
    }
  }
#line 41 "parser.rl"
	{
    if (parser->request_uri != NULL) {
      parser->request_uri(parser->data, PTR_TO(mark), LEN(mark, p));
    }
  }
	goto st5;
tr55:
#line 53 "parser.rl"
	{ 
    if (parser->query_string != NULL) {
      parser->query_string(parser->data, PTR_TO(query_start), LEN(query_start, p));
    }
  }
#line 41 "parser.rl"
	{
    if (parser->request_uri != NULL) {
      parser->request_uri(parser->data, PTR_TO(mark), LEN(mark, p));
    }
  }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 235 "parser.c"
	if ( (*p) == 72 )
		goto tr10;
	goto st0;
tr10:
#line 22 "parser.rl"
	{MARK(mark, p); }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 247 "parser.c"
	if ( (*p) == 84 )
		goto st7;
	goto st0;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
	if ( (*p) == 84 )
		goto st8;
	goto st0;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
	if ( (*p) == 80 )
		goto st9;
	goto st0;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
	if ( (*p) == 47 )
		goto st10;
	goto st0;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st11;
	goto st0;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
	if ( (*p) == 46 )
		goto st12;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st11;
	goto st0;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st13;
	goto st0;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
	if ( (*p) == 13 )
		goto tr18;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st13;
	goto st0;
tr18:
#line 59 "parser.rl"
	{	
    if (parser->http_version != NULL) {
      parser->http_version(parser->data, PTR_TO(mark), LEN(mark, p));
    }
  }
	goto st14;
tr26:
#line 30 "parser.rl"
	{ MARK(mark, p); }
#line 31 "parser.rl"
	{ 
    if (parser->http_field != NULL) {
      parser->http_field(parser->data, PTR_TO(field_start), parser->field_len, PTR_TO(mark), LEN(mark, p));
    }
  }
	goto st14;
tr29:
#line 31 "parser.rl"
	{ 
    if (parser->http_field != NULL) {
      parser->http_field(parser->data, PTR_TO(field_start), parser->field_len, PTR_TO(mark), LEN(mark, p));
    }
  }
	goto st14;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
#line 334 "parser.c"
	if ( (*p) == 10 )
		goto st15;
	goto st0;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
	switch( (*p) ) {
		case 13: goto st16;
		case 33: goto tr21;
		case 124: goto tr21;
		case 126: goto tr21;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto tr21;
		} else if ( (*p) >= 35 )
			goto tr21;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto tr21;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto tr21;
		} else
			goto tr21;
	} else
		goto tr21;
	goto st0;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
	if ( (*p) == 10 )
		goto tr22;
	goto st0;
tr22:
#line 71 "parser.rl"
	{ 
    parser->body_start = p - buffer + 1; 
    if (parser->header_done != NULL) {
      parser->header_done(parser->data, p + 1, pe - p - 1);
    }
    {p++; cs = 58; goto _out;}
  }
	goto st58;
st58:
	if ( ++p == pe )
		goto _test_eof58;
case 58:
#line 387 "parser.c"
	goto st0;
tr21:
#line 25 "parser.rl"
	{ MARK(field_start, p); }
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 397 "parser.c"
	switch( (*p) ) {
		case 33: goto st17;
		case 58: goto tr24;
		case 124: goto st17;
		case 126: goto st17;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st17;
		} else if ( (*p) >= 35 )
			goto st17;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st17;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st17;
		} else
			goto st17;
	} else
		goto st17;
	goto st0;
tr24:
#line 26 "parser.rl"
	{ 
    parser->field_len = LEN(field_start, p);
  }
	goto st18;
tr27:
#line 30 "parser.rl"
	{ MARK(mark, p); }
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 436 "parser.c"
	switch( (*p) ) {
		case 13: goto tr26;
		case 32: goto tr27;
	}
	goto tr25;
tr25:
#line 30 "parser.rl"
	{ MARK(mark, p); }
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 450 "parser.c"
	if ( (*p) == 13 )
		goto tr29;
	goto st19;
tr9:
#line 41 "parser.rl"
	{
    if (parser->request_uri != NULL) {
      parser->request_uri(parser->data, PTR_TO(mark), LEN(mark, p));
    }
  }
	goto st20;
tr45:
#line 65 "parser.rl"
	{
    if (parser->request_path != NULL) {
      parser->request_path(parser->data, PTR_TO(mark), LEN(mark,p));
    }
  }
#line 41 "parser.rl"
	{
    if (parser->request_uri != NULL) {
      parser->request_uri(parser->data, PTR_TO(mark), LEN(mark, p));
    }
  }
	goto st20;
tr52:
#line 52 "parser.rl"
	{MARK(query_start, p); }
#line 53 "parser.rl"
	{ 
    if (parser->query_string != NULL) {
      parser->query_string(parser->data, PTR_TO(query_start), LEN(query_start, p));
    }
  }
#line 41 "parser.rl"
	{
    if (parser->request_uri != NULL) {
      parser->request_uri(parser->data, PTR_TO(mark), LEN(mark, p));
    }
  }
	goto st20;
tr56:
#line 53 "parser.rl"
	{ 
    if (parser->query_string != NULL) {
      parser->query_string(parser->data, PTR_TO(query_start), LEN(query_start, p));
    }
  }
#line 41 "parser.rl"
	{
    if (parser->request_uri != NULL) {
      parser->request_uri(parser->data, PTR_TO(mark), LEN(mark, p));
    }
  }
	goto st20;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
#line 510 "parser.c"
	switch( (*p) ) {
		case 32: goto tr31;
		case 35: goto st0;
		case 37: goto tr32;
		case 127: goto st0;
	}
	if ( 0 <= (*p) && (*p) <= 31 )
		goto st0;
	goto tr30;
tr30:
#line 22 "parser.rl"
	{MARK(mark, p); }
	goto st21;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
#line 528 "parser.c"
	switch( (*p) ) {
		case 32: goto tr34;
		case 35: goto st0;
		case 37: goto st22;
		case 127: goto st0;
	}
	if ( 0 <= (*p) && (*p) <= 31 )
		goto st0;
	goto st21;
tr32:
#line 22 "parser.rl"
	{MARK(mark, p); }
	goto st22;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
#line 546 "parser.c"
	if ( (*p) == 117 )
		goto st24;
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st23;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st23;
	} else
		goto st23;
	goto st0;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st21;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st21;
	} else
		goto st21;
	goto st0;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st23;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st23;
	} else
		goto st23;
	goto st0;
tr5:
#line 22 "parser.rl"
	{MARK(mark, p); }
	goto st25;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
#line 592 "parser.c"
	switch( (*p) ) {
		case 43: goto st25;
		case 58: goto st26;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st25;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto st25;
		} else if ( (*p) >= 65 )
			goto st25;
	} else
		goto st25;
	goto st0;
tr7:
#line 22 "parser.rl"
	{MARK(mark, p); }
	goto st26;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
#line 617 "parser.c"
	switch( (*p) ) {
		case 32: goto tr8;
		case 35: goto tr9;
		case 37: goto st27;
		case 127: goto st0;
	}
	if ( 0 <= (*p) && (*p) <= 31 )
		goto st0;
	goto st26;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
	if ( (*p) == 117 )
		goto st29;
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st28;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st28;
	} else
		goto st28;
	goto st0;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st26;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st26;
	} else
		goto st26;
	goto st0;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st28;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st28;
	} else
		goto st28;
	goto st0;
tr6:
#line 22 "parser.rl"
	{MARK(mark, p); }
	goto st30;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
#line 676 "parser.c"
	switch( (*p) ) {
		case 32: goto tr44;
		case 35: goto tr45;
		case 37: goto st31;
		case 63: goto tr47;
		case 127: goto st0;
	}
	if ( 0 <= (*p) && (*p) <= 31 )
		goto st0;
	goto st30;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
	if ( (*p) == 117 )
		goto st33;
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st32;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st32;
	} else
		goto st32;
	goto st0;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st30;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st30;
	} else
		goto st30;
	goto st0;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st32;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st32;
	} else
		goto st32;
	goto st0;
tr47:
#line 65 "parser.rl"
	{
    if (parser->request_path != NULL) {
      parser->request_path(parser->data, PTR_TO(mark), LEN(mark,p));
    }
  }
	goto st34;
st34:
	if ( ++p == pe )
		goto _test_eof34;
case 34:
#line 740 "parser.c"
	switch( (*p) ) {
		case 32: goto tr51;
		case 35: goto tr52;
		case 37: goto tr53;
		case 127: goto st0;
	}
	if ( 0 <= (*p) && (*p) <= 31 )
		goto st0;
	goto tr50;
tr50:
#line 52 "parser.rl"
	{MARK(query_start, p); }
	goto st35;
st35:
	if ( ++p == pe )
		goto _test_eof35;
case 35:
#line 758 "parser.c"
	switch( (*p) ) {
		case 32: goto tr55;
		case 35: goto tr56;
		case 37: goto st36;
		case 127: goto st0;
	}
	if ( 0 <= (*p) && (*p) <= 31 )
		goto st0;
	goto st35;
tr53:
#line 52 "parser.rl"
	{MARK(query_start, p); }
	goto st36;
st36:
	if ( ++p == pe )
		goto _test_eof36;
case 36:
#line 776 "parser.c"
	if ( (*p) == 117 )
		goto st38;
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st37;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st37;
	} else
		goto st37;
	goto st0;
st37:
	if ( ++p == pe )
		goto _test_eof37;
case 37:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st35;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st35;
	} else
		goto st35;
	goto st0;
st38:
	if ( ++p == pe )
		goto _test_eof38;
case 38:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st37;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st37;
	} else
		goto st37;
	goto st0;
st39:
	if ( ++p == pe )
		goto _test_eof39;
case 39:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st40;
		case 95: goto st40;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st40;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st40;
	} else
		goto st40;
	goto st0;
st40:
	if ( ++p == pe )
		goto _test_eof40;
case 40:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st41;
		case 95: goto st41;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st41;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st41;
	} else
		goto st41;
	goto st0;
st41:
	if ( ++p == pe )
		goto _test_eof41;
case 41:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st42;
		case 95: goto st42;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st42;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st42;
	} else
		goto st42;
	goto st0;
st42:
	if ( ++p == pe )
		goto _test_eof42;
case 42:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st43;
		case 95: goto st43;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st43;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st43;
	} else
		goto st43;
	goto st0;
st43:
	if ( ++p == pe )
		goto _test_eof43;
case 43:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st44;
		case 95: goto st44;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st44;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st44;
	} else
		goto st44;
	goto st0;
st44:
	if ( ++p == pe )
		goto _test_eof44;
case 44:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st45;
		case 95: goto st45;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st45;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st45;
	} else
		goto st45;
	goto st0;
st45:
	if ( ++p == pe )
		goto _test_eof45;
case 45:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st46;
		case 95: goto st46;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st46;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st46;
	} else
		goto st46;
	goto st0;
st46:
	if ( ++p == pe )
		goto _test_eof46;
case 46:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st47;
		case 95: goto st47;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st47;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st47;
	} else
		goto st47;
	goto st0;
st47:
	if ( ++p == pe )
		goto _test_eof47;
case 47:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st48;
		case 95: goto st48;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st48;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st48;
	} else
		goto st48;
	goto st0;
st48:
	if ( ++p == pe )
		goto _test_eof48;
case 48:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st49;
		case 95: goto st49;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st49;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st49;
	} else
		goto st49;
	goto st0;
st49:
	if ( ++p == pe )
		goto _test_eof49;
case 49:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st50;
		case 95: goto st50;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st50;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st50;
	} else
		goto st50;
	goto st0;
st50:
	if ( ++p == pe )
		goto _test_eof50;
case 50:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st51;
		case 95: goto st51;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st51;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st51;
	} else
		goto st51;
	goto st0;
st51:
	if ( ++p == pe )
		goto _test_eof51;
case 51:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st52;
		case 95: goto st52;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st52;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st52;
	} else
		goto st52;
	goto st0;
st52:
	if ( ++p == pe )
		goto _test_eof52;
case 52:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st53;
		case 95: goto st53;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st53;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st53;
	} else
		goto st53;
	goto st0;
st53:
	if ( ++p == pe )
		goto _test_eof53;
case 53:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st54;
		case 95: goto st54;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st54;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st54;
	} else
		goto st54;
	goto st0;
st54:
	if ( ++p == pe )
		goto _test_eof54;
case 54:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st55;
		case 95: goto st55;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st55;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st55;
	} else
		goto st55;
	goto st0;
st55:
	if ( ++p == pe )
		goto _test_eof55;
case 55:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st56;
		case 95: goto st56;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st56;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st56;
	} else
		goto st56;
	goto st0;
st56:
	if ( ++p == pe )
		goto _test_eof56;
case 56:
	switch( (*p) ) {
		case 32: goto tr2;
		case 36: goto st57;
		case 95: goto st57;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st57;
	} else if ( (*p) > 57 ) {
		if ( 65 <= (*p) && (*p) <= 90 )
			goto st57;
	} else
		goto st57;
	goto st0;
st57:
	if ( ++p == pe )
		goto _test_eof57;
case 57:
	if ( (*p) == 32 )
		goto tr2;
	goto st0;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof14: cs = 14; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
	_test_eof16: cs = 16; goto _test_eof; 
	_test_eof58: cs = 58; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof26: cs = 26; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof42: cs = 42; goto _test_eof; 
	_test_eof43: cs = 43; goto _test_eof; 
	_test_eof44: cs = 44; goto _test_eof; 
	_test_eof45: cs = 45; goto _test_eof; 
	_test_eof46: cs = 46; goto _test_eof; 
	_test_eof47: cs = 47; goto _test_eof; 
	_test_eof48: cs = 48; goto _test_eof; 
	_test_eof49: cs = 49; goto _test_eof; 
	_test_eof50: cs = 50; goto _test_eof; 
	_test_eof51: cs = 51; goto _test_eof; 
	_test_eof52: cs = 52; goto _test_eof; 
	_test_eof53: cs = 53; goto _test_eof; 
	_test_eof54: cs = 54; goto _test_eof; 
	_test_eof55: cs = 55; goto _test_eof; 
	_test_eof56: cs = 56; goto _test_eof; 
	_test_eof57: cs = 57; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 116 "parser.rl"

  parser->cs = cs;
  parser->nread += p - (buffer + off);

  assert(p <= pe && "buffer overflow after parsing execute");
  assert(parser->nread <= len && "nread longer than length");
  assert(parser->body_start <= len && "body starts after buffer end");
  assert(parser->mark < len && "mark is after buffer end");
  assert(parser->field_len <= len && "field has length longer than whole buffer");
  assert(parser->field_start < len && "field starts after buffer end");

  if(parser->body_start) {
    /* final \r\n combo encountered so stop right here */
    parser->nread++;
  }

  return(parser->nread);
}

int thin_http_parser_finish(http_parser *parser)
{
  int cs = parser->cs;


  parser->cs = cs;

  if (thin_http_parser_has_error(parser) ) {
    return -1;
  } else if (thin_http_parser_is_finished(parser) ) {
    return 1;
  } else {
    return 0;
  }
}

int thin_http_parser_has_error(http_parser *parser) {
  return parser->cs == http_parser_error;
}

int thin_http_parser_is_finished(http_parser *parser) {
  return parser->cs == http_parser_first_final;
}
