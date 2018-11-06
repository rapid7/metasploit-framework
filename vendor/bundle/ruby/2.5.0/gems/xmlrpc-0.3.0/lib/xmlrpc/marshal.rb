# frozen_string_literal: false
#
# Copyright (C) 2001, 2002, 2003 by Michael Neumann (mneumann@ntecs.de)
#
# $Id$
#

require "xmlrpc/parser"
require "xmlrpc/create"
require "xmlrpc/config"
require "xmlrpc/utils"

module XMLRPC # :nodoc:

  # Marshalling of XMLRPC::Create#methodCall and XMLRPC::Create#methodResponse
  class Marshal
    include ParserWriterChooseMixin

    class << self

      def dump_call( methodName, *params )
        new.dump_call( methodName, *params )
      end

      def dump_response( param )
        new.dump_response( param )
      end

      def load_call( stringOrReadable )
        new.load_call( stringOrReadable )
      end

      def load_response( stringOrReadable )
        new.load_response( stringOrReadable )
      end

      alias dump dump_response
      alias load load_response

    end # class self

    def initialize( parser = nil, writer = nil )
      set_parser( parser )
      set_writer( writer )
    end

    def dump_call( methodName, *params )
      create.methodCall( methodName, *params )
    end

    def dump_response( param )
      create.methodResponse( ! param.kind_of?( XMLRPC::FaultException ) , param )
    end

    # Returns <code>[ methodname, params ]</code>
    def load_call( stringOrReadable )
      parser.parseMethodCall( stringOrReadable )
    end

    # Returns +paramOrFault+
    def load_response( stringOrReadable )
      parser.parseMethodResponse( stringOrReadable )[1]
    end

  end # class Marshal

end
