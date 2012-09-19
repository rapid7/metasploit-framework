#ifndef NOKOGIRI_XML_NODE_SET
#define NOKOGIRI_XML_NODE_SET

#include <nokogiri.h>
void init_xml_node_set();

extern VALUE cNokogiriXmlNodeSet ;
VALUE Nokogiri_wrap_xml_node_set(xmlNodeSetPtr node_set, VALUE document) ;

typedef struct _nokogiriNodeSetTuple {
  xmlNodeSetPtr node_set;
  st_table     *namespaces;
} nokogiriNodeSetTuple;
#endif
