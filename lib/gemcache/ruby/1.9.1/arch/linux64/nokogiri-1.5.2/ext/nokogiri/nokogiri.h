#ifndef NOKOGIRI_NATIVE
#define NOKOGIRI_NATIVE

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#ifdef USE_INCLUDED_VASPRINTF
int vasprintf (char **strp, const char *fmt, va_list ap);
#else

#define _GNU_SOURCE
#  include <stdio.h>
#undef _GNU_SOURCE

#endif

#include <libxml/parser.h>
#include <libxml/entities.h>
#include <libxml/parserInternals.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlsave.h>
#include <libxml/xmlschemas.h>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/relaxng.h>
#include <libxml/xinclude.h>
#include <libxslt/extensions.h>
#include <libxml/c14n.h>
#include <ruby.h>

#ifdef HAVE_RUBY_ENCODING_H
#include <ruby/st.h>
#else
#include <st.h>
#endif

#ifndef UNUSED
# if defined(__GNUC__)
#  define MAYBE_UNUSED(name) name __attribute__((unused))
#  define UNUSED(name) MAYBE_UNUSED(UNUSED_ ## name)
# else
#  define MAYBE_UNUSED(name) name
#  define UNUSED(name) name
# endif
#endif

#ifndef NORETURN
# if defined(__GNUC__)
#  define NORETURN(name) __attribute__((noreturn)) name
# else
#  define NORETURN(name) name
# endif
#endif

#ifdef HAVE_RUBY_ENCODING_H

#include <ruby/encoding.h>

#define NOKOGIRI_STR_NEW2(str) \
  NOKOGIRI_STR_NEW(str, strlen((const char *)(str)))

#define NOKOGIRI_STR_NEW(str, len) \
  rb_external_str_new_with_enc((const char *)(str), (long)(len), rb_utf8_encoding())

#else

#define NOKOGIRI_STR_NEW2(str) \
  rb_str_new2((const char *)(str))

#define NOKOGIRI_STR_NEW(str, len) \
  rb_str_new((const char *)(str), (long)(len))
#endif

#define RBSTR_OR_QNIL(_str) \
  (_str ? NOKOGIRI_STR_NEW2(_str) : Qnil)

#include <xml_libxml2_hacks.h>

#include <xml_io.h>
#include <xml_document.h>
#include <html_entity_lookup.h>
#include <html_document.h>
#include <xml_node.h>
#include <xml_text.h>
#include <xml_cdata.h>
#include <xml_attr.h>
#include <xml_processing_instruction.h>
#include <xml_entity_reference.h>
#include <xml_document_fragment.h>
#include <xml_comment.h>
#include <xml_node_set.h>
#include <xml_dtd.h>
#include <xml_attribute_decl.h>
#include <xml_element_decl.h>
#include <xml_entity_decl.h>
#include <xml_xpath_context.h>
#include <xml_element_content.h>
#include <xml_sax_parser_context.h>
#include <xml_sax_parser.h>
#include <xml_sax_push_parser.h>
#include <xml_reader.h>
#include <html_sax_parser_context.h>
#include <html_sax_push_parser.h>
#include <xslt_stylesheet.h>
#include <xml_syntax_error.h>
#include <xml_schema.h>
#include <xml_relax_ng.h>
#include <html_element_description.h>
#include <xml_namespace.h>
#include <xml_encoding_handler.h>

extern VALUE mNokogiri ;
extern VALUE mNokogiriXml ;
extern VALUE mNokogiriXmlSax ;
extern VALUE mNokogiriHtml ;
extern VALUE mNokogiriHtmlSax ;
extern VALUE mNokogiriXslt ;

#define NOKOGIRI_ROOT_NODE(_node) \
  st_insert(((nokogiriTuplePtr)(_node)->doc->_private)->unlinkedNodes, (st_data_t)(_node), (st_data_t)(_node))

#define NOKOGIRI_ROOT_NSDEF(_nsDef, _doc)     \
  st_insert(((nokogiriTuplePtr)(_doc)->_private)->unlinkedNodes, (st_data_t)(_nsDef), (st_data_t)(_nsDef))

#ifdef DEBUG

#define NOKOGIRI_DEBUG_START(p) if (getenv("NOKOGIRI_NO_FREE")) return ; if (getenv("NOKOGIRI_DEBUG")) fprintf(stderr,"nokogiri: %s:%d %p start\n", __FILE__, __LINE__, p);
#define NOKOGIRI_DEBUG_END(p) if (getenv("NOKOGIRI_DEBUG")) fprintf(stderr,"nokogiri: %s:%d %p end\n", __FILE__, __LINE__, p);

#else

#define NOKOGIRI_DEBUG_START(p)
#define NOKOGIRI_DEBUG_END(p)

#endif

#ifndef RSTRING_PTR
#define RSTRING_PTR(s) (RSTRING(s)->ptr)
#endif

#ifndef RSTRING_LEN
#define RSTRING_LEN(s) (RSTRING(s)->len)
#endif

#ifndef RARRAY_PTR
#define RARRAY_PTR(a) RARRAY(a)->ptr
#endif

#ifndef RARRAY_LEN
#define RARRAY_LEN(a) RARRAY(a)->len
#endif

#ifndef __builtin_expect
# if defined(__GNUC__)
#  define __builtin_expect(expr, c) __builtin_expect((long)(expr), (long)(c))
# endif
#endif

#endif
