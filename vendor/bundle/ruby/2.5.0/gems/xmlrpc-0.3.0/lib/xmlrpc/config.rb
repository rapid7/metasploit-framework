# frozen_string_literal: false
#
# $Id$
# Configuration file for XML-RPC for Ruby
#

module XMLRPC # :nodoc:

  module Config

    # or XMLWriter::XMLParser
    DEFAULT_WRITER = XMLWriter::Simple

    # === Available parsers
    #
    # * XMLParser::REXMLStreamParser
    # * XMLParser::LibXMLStreamParser
    DEFAULT_PARSER = XMLParser::REXMLStreamParser

    # enable <code><nil/></code> tag
    ENABLE_NIL_CREATE    = false
    ENABLE_NIL_PARSER    = false

    # allows integers greater than 32-bit if +true+
    ENABLE_BIGINT        = false

    # enable marshalling Ruby objects which include XMLRPC::Marshallable
    ENABLE_MARSHALLING   = true

    # enable multiCall extension by default
    ENABLE_MULTICALL     = false

    # enable Introspection extension by default
    ENABLE_INTROSPECTION = false

  end

end

