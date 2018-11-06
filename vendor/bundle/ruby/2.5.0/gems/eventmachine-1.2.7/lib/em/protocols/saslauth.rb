#--
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 15 November 2006
# 
# See EventMachine and EventMachine::Connection for documentation and
# usage examples.
#
#----------------------------------------------------------------------------
#
# Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
# Gmail: blackhedd
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of either: 1) the GNU General Public License
# as published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version; or 2) Ruby's License.
# 
# See the file COPYING for complete licensing information.
#
#---------------------------------------------------------------------------
#
# 
# 

module EventMachine
  module Protocols

    # Implements SASL authd.
    # This is a very, very simple protocol that mimics the one used
    # by saslauthd and pwcheck, two outboard daemons included in the
    # standard SASL library distro.
    # The only thing this is really suitable for is SASL PLAIN
    # (user+password) authentication, but the SASL libs that are
    # linked into standard servers (like imapd and sendmail) implement
    # the other ones.
    #
    # SASL-auth is intended for reasonably fast operation inside a
    # single machine, so it has no transport-security (although there
    # have been multi-machine extensions incorporating transport-layer
    # encryption).
    #
    # The standard saslauthd module generally runs privileged and does
    # its work by referring to the system-account files.
    #
    # This feature was added to EventMachine to enable the development
    # of custom authentication/authorization engines for standard servers.
    #
    # To use SASLauth, include it in a class that subclasses EM::Connection,
    # and reimplement the validate method.
    #
    # The typical way to incorporate this module into an authentication
    # daemon would be to set it as the handler for a UNIX-domain socket.
    # The code might look like this:
    #
    #  EM.start_unix_domain_server( "/var/run/saslauthd/mux", MyHandler )
    #  File.chmod( 0777, "/var/run/saslauthd/mux")
    #
    # The chmod is probably needed to ensure that unprivileged clients can
    # access the UNIX-domain socket.
    #
    # It's also a very good idea to drop superuser privileges (if any), after
    # the UNIX-domain socket has been opened.
    #--
    # Implementation details: assume the client can send us pipelined requests,
    # and that the client will close the connection.
    #
    # The client sends us four values, each encoded as a two-byte length field in
    # network order followed by the specified number of octets.
    # The fields specify the username, password, service name (such as imap),
    # and the "realm" name. We send back the barest minimum reply, a single
    # field also encoded as a two-octet length in network order, followed by
    # either "NO" or "OK" - simplicity itself.
    #
    # We enforce a maximum field size just as a sanity check.
    # We do NOT automatically time out the connection.
    #
    # The code we use to parse out the values is ugly and probably slow.
    # Improvements welcome.
    #
    module SASLauth

      MaxFieldSize = 128*1024
      def post_init
        super
        @sasl_data = ""
        @sasl_values = []
      end

      def receive_data data
        @sasl_data << data
        while @sasl_data.length >= 2
          len = (@sasl_data[0,2].unpack("n")).first
          raise "SASL Max Field Length exceeded" if len > MaxFieldSize
          if @sasl_data.length >= (len + 2)
            @sasl_values << @sasl_data[2,len]
            @sasl_data.slice!(0...(2+len))
            if @sasl_values.length == 4
              send_data( validate(*@sasl_values) ? "\0\002OK" : "\0\002NO" )
              @sasl_values.clear
            end
          else
            break
          end
        end
      end

      def validate username, psw, sysname, realm
        p username
        p psw
        p sysname
        p realm
        true
      end
    end

    # Implements the SASL authd client protocol.
    # This is a very, very simple protocol that mimics the one used
    # by saslauthd and pwcheck, two outboard daemons included in the
    # standard SASL library distro.
    # The only thing this is really suitable for is SASL PLAIN
    # (user+password) authentication, but the SASL libs that are
    # linked into standard servers (like imapd and sendmail) implement
    # the other ones.
    #
    # You can use this module directly as a handler for EM Connections,
    # or include it in a module or handler class of your own.
    #
    # First connect to a SASL server (it's probably a TCP server, or more
    # likely a Unix-domain socket). Then call the #validate? method,
    # passing at least a username and a password. #validate? returns
    # a Deferrable which will either succeed or fail, depending
    # on the status of the authentication operation.
    #
    module SASLauthclient
      MaxFieldSize = 128*1024

      def validate? username, psw, sysname=nil, realm=nil

        str = [username, psw, sysname, realm].map {|m|
          [(m || "").length, (m || "")]
        }.flatten.pack( "nA*" * 4 )
        send_data str

        d = EM::DefaultDeferrable.new
        @queries.unshift d
        d
      end

      def post_init
        @sasl_data = ""
        @queries = []
      end

      def receive_data data
        @sasl_data << data

        while @sasl_data.length > 2
          len = (@sasl_data[0,2].unpack("n")).first
          raise "SASL Max Field Length exceeded" if len > MaxFieldSize
          if @sasl_data.length >= (len + 2)
            val = @sasl_data[2,len]
            @sasl_data.slice!(0...(2+len))
            q = @queries.pop
            (val == "NO") ? q.fail : q.succeed
          else
            break
          end
        end
      end
    end

  end
end
