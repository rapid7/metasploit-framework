%%{
  
  machine http_parser_common;

#### HTTP PROTOCOL GRAMMAR
# line endings
  CRLF = "\r\n";

# character types
  CTL = (cntrl | 127);
  safe = ("$" | "-" | "_" | ".");
  extra = ("!" | "*" | "'" | "(" | ")" | ",");
  reserved = (";" | "/" | "?" | ":" | "@" | "&" | "=" | "+");
  sorta_safe = ("\"" | "<" | ">");
  unsafe = (CTL | " " | "#" | "%" | sorta_safe);
  national = any -- (alpha | digit | reserved | extra | safe | unsafe);
  unreserved = (alpha | digit | safe | extra | national);
  escape = ("%" "u"? xdigit xdigit);
  uchar = (unreserved | escape | sorta_safe);
  pchar = (uchar | ":" | "@" | "&" | "=" | "+");
  tspecials = ("(" | ")" | "<" | ">" | "@" | "," | ";" | ":" | "\\" | "\"" | "/" | "[" | "]" | "?" | "=" | "{" | "}" | " " | "\t");

# elements
  token = (ascii -- (CTL | tspecials));

# URI schemes and absolute paths
  scheme = ( "http"i ("s"i)? );
  hostname = ((alnum | "-" | "." | "_")+ | ("[" (":" | xdigit)+ "]"));
  host_with_port = (hostname (":" digit*)?);
  userinfo = ((unreserved | escape | ";" | ":" | "&" | "=" | "+")+ "@")*;

  path = ( pchar+ ( "/" pchar* )* ) ;
  query = ( uchar | reserved )* %query_string ;
  param = ( pchar | "/" )* ;
  params = ( param ( ";" param )* ) ;
  rel_path = (path? (";" params)? %request_path) ("?" %start_query query)?;
  absolute_path = ( "/"+ rel_path );
  path_uri = absolute_path > mark %request_uri;
  Absolute_URI = (scheme "://" userinfo host_with_port path_uri);

  Request_URI = ((absolute_path | "*") >mark %request_uri) | Absolute_URI;
  Fragment = ( uchar | reserved )* >mark %fragment;
  Method = ( upper | digit | safe ){1,20} >mark %request_method;

  http_number = ( digit+ "." digit+ ) ;
  HTTP_Version = ( "HTTP/" http_number ) >mark %http_version ;
  Request_Line = ( Method " " Request_URI ("#" Fragment){0,1} " " HTTP_Version CRLF ) ;

  field_name = ( token -- ":" )+ >start_field %write_field;

  field_value = any* >start_value %write_value;

  message_header = field_name ":" " "* field_value :> CRLF;

  Request = Request_Line ( message_header )* ( CRLF @done );

main := Request;

}%%
