#include <nokogiri.h>

VALUE mNokogiri ;
VALUE mNokogiriXml ;
VALUE mNokogiriHtml ;
VALUE mNokogiriXslt ;
VALUE mNokogiriXmlSax ;
VALUE mNokogiriHtmlSax ;

#ifdef USE_INCLUDED_VASPRINTF
/*
 * I srsly hate windows.  it doesn't have vasprintf.
 * Thank you Geoffroy Couprie for this implementation of vasprintf!
 */
int vasprintf (char **strp, const char *fmt, va_list ap)
{
  int len = vsnprintf (NULL, 0, fmt, ap) + 1;
  char *res = (char *)malloc((unsigned int)len);
  if (res == NULL)
      return -1;
  *strp = res;
  return vsnprintf(res, (unsigned int)len, fmt, ap);
}
#endif

#ifdef USING_SYSTEM_ALLOCATOR_LIBRARY /* Ruby Enterprise Edition with tcmalloc */
void vasprintf_free (void *p)
{
  system_free(p);
}
#else
void vasprintf_free (void *p)
{
  free(p);
}
#endif

#ifdef HAVE_RUBY_UTIL_H
#include "ruby/util.h"
#else
#ifndef __MACRUBY__
#include "util.h"
#endif
#endif

void Init_nokogiri()
{
#ifndef __MACRUBY__
  xmlMemSetup(
      (xmlFreeFunc)ruby_xfree,
      (xmlMallocFunc)ruby_xmalloc,
      (xmlReallocFunc)ruby_xrealloc,
      ruby_strdup
  );
#endif

  mNokogiri         = rb_define_module("Nokogiri");
  mNokogiriXml      = rb_define_module_under(mNokogiri, "XML");
  mNokogiriHtml     = rb_define_module_under(mNokogiri, "HTML");
  mNokogiriXslt     = rb_define_module_under(mNokogiri, "XSLT");
  mNokogiriXmlSax   = rb_define_module_under(mNokogiriXml, "SAX");
  mNokogiriHtmlSax  = rb_define_module_under(mNokogiriHtml, "SAX");

  rb_const_set( mNokogiri,
                rb_intern("LIBXML_VERSION"),
                NOKOGIRI_STR_NEW2(LIBXML_DOTTED_VERSION)
              );
  rb_const_set( mNokogiri,
                rb_intern("LIBXML_PARSER_VERSION"),
                NOKOGIRI_STR_NEW2(xmlParserVersion)
              );

#ifdef LIBXML_ICONV_ENABLED
  rb_const_set(mNokogiri, rb_intern("LIBXML_ICONV_ENABLED"), Qtrue);
#else
  rb_const_set(mNokogiri, rb_intern("LIBXML_ICONV_ENABLED"), Qfalse);
#endif

  xmlInitParser();

  init_xml_document();
  init_html_document();
  init_xml_node();
  init_xml_document_fragment();
  init_xml_text();
  init_xml_cdata();
  init_xml_processing_instruction();
  init_xml_attr();
  init_xml_entity_reference();
  init_xml_comment();
  init_xml_node_set();
  init_xml_xpath_context();
  init_xml_sax_parser_context();
  init_xml_sax_parser();
  init_xml_sax_push_parser();
  init_xml_reader();
  init_xml_dtd();
  init_xml_element_content();
  init_xml_attribute_decl();
  init_xml_element_decl();
  init_xml_entity_decl();
  init_xml_namespace();
  init_html_sax_parser_context();
  init_html_sax_push_parser();
  init_xslt_stylesheet();
  init_xml_syntax_error();
  init_html_entity_lookup();
  init_html_element_description();
  init_xml_schema();
  init_xml_relax_ng();
  init_nokogiri_io();
  init_xml_encoding_handler();
}
