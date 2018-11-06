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
# Copyright (C) 2006-08 by Francis Cianfrocca. All Rights Reserved.
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

require 'postgres-pr/message'
require 'postgres-pr/connection'
require 'stringio'

# @private
class StringIO
  # Reads exactly +n+ bytes.
  #
  # If the data read is nil an EOFError is raised.
  #
  # If the data read is too short an IOError is raised
  def readbytes(n)
    str = read(n)
    if str == nil
      raise EOFError, "End of file reached"
    end
    if str.size < n
      raise IOError, "data truncated"
    end
    str
  end
  alias read_exactly_n_bytes readbytes
end


module EventMachine
  module Protocols
    # PROVISIONAL IMPLEMENTATION of an evented Postgres client.
    # This implements version 3 of the Postgres wire protocol, which will work
    # with any Postgres version from roughly 7.4 onward.
    #
    # Objective: we want to access Postgres databases without requiring threads.
    # Until now this has been a problem because the Postgres client implementations
    # have all made use of blocking I/O calls, which is incompatible with a
    # thread-free evented model.
    #
    # But rather than re-implement the Postgres Wire3 protocol, we're taking advantage
    # of the existing postgres-pr library, which was originally written by Michael
    # Neumann but (at this writing) appears to be no longer maintained. Still, it's
    # in basically a production-ready state, and the wire protocol isn't that complicated
    # anyway.
    #
    # We're tucking in a bunch of require statements that may not be present in garden-variety
    # EM installations. Until we find a good way to only require these if a program
    # requires postgres, this file will need to be required explicitly.
    #
    # We need to monkeypatch StringIO because it lacks the #readbytes method needed
    # by postgres-pr.
    # The StringIO monkeypatch is lifted from the standard library readbytes.rb,
    # which adds method #readbytes directly to class IO. But StringIO is not a subclass of IO.
    # It is modified to raise an IOError instead of TruncatedDataException since the exception is unused.
    #
    # We cloned the handling of postgres messages from lib/postgres-pr/connection.rb
    # in the postgres-pr library, and modified it for event-handling.
    #
    # TODO: The password handling in dispatch_conn_message is totally incomplete.
    #
    #
    # We return Deferrables from the user-level operations surfaced by this interface.
    # Experimentally, we're using the pattern of always returning a boolean value as the
    # first argument of a deferrable callback to indicate success or failure. This is
    # instead of the traditional pattern of calling Deferrable#succeed or #fail, and
    # requiring the user to define both a callback and an errback function.
    #
    # === Usage
    #  EM.run {
    #    db = EM.connect_unix_domain( "/tmp/.s.PGSQL.5432", EM::P::Postgres3 )
    #    db.connect( dbname, username, psw ).callback do |status|
    #      if status
    #        db.query( "select * from some_table" ).callback do |status, result, errors|
    #          if status
    #            result.rows.each do |row|
    #              p row
    #            end
    #          end
    #        end
    #      end
    #    end
    #  }
    class Postgres3 < EventMachine::Connection
      include PostgresPR

      def initialize
        @data = ""
        @params = {}
      end

      def connect db, user, psw=nil
        d = EM::DefaultDeferrable.new
        d.timeout 15

        if @pending_query || @pending_conn
          d.succeed false, "Operation already in progress"
        else
          @pending_conn = d
          prms = {"user"=>user, "database"=>db}
          @user = user
          if psw
            @password = psw
            #prms["password"] = psw
          end
          send_data PostgresPR::StartupMessage.new( 3 << 16, prms ).dump
        end

        d
      end

      def query sql
        d = EM::DefaultDeferrable.new
        d.timeout 15

        if @pending_query || @pending_conn
          d.succeed false, "Operation already in progress"
        else
          @r = PostgresPR::Connection::Result.new
          @e = []
          @pending_query = d
          send_data PostgresPR::Query.dump(sql)
        end

        d
      end


      def receive_data data
        @data << data
        while @data.length >= 5
          pktlen = @data[1...5].unpack("N").first
          if @data.length >= (1 + pktlen)
            pkt = @data.slice!(0...(1+pktlen))
            m = StringIO.open( pkt, "r" ) {|io| PostgresPR::Message.read( io ) }
            if @pending_conn
              dispatch_conn_message m
            elsif @pending_query
              dispatch_query_message m
            else
              raise "Unexpected message from database"
            end
          else
            break # very important, break out of the while
          end
        end
      end


      def unbind
        if o = (@pending_query || @pending_conn)
          o.succeed false, "lost connection"
        end
      end

      # Cloned and modified from the postgres-pr.
      def dispatch_conn_message msg
        case msg
        when AuthentificationClearTextPassword
          raise ArgumentError, "no password specified" if @password.nil?
          send_data PasswordMessage.new(@password).dump

        when AuthentificationCryptPassword
          raise ArgumentError, "no password specified" if @password.nil?
          send_data PasswordMessage.new(@password.crypt(msg.salt)).dump

        when AuthentificationMD5Password
          raise ArgumentError, "no password specified" if @password.nil?
          require 'digest/md5'

          m = Digest::MD5.hexdigest(@password + @user)
          m = Digest::MD5.hexdigest(m + msg.salt)
          m = 'md5' + m
          send_data PasswordMessage.new(m).dump

        when AuthentificationKerberosV4, AuthentificationKerberosV5, AuthentificationSCMCredential
          raise "unsupported authentification"

        when AuthentificationOk
        when ErrorResponse
          raise msg.field_values.join("\t")
        when NoticeResponse
          @notice_processor.call(msg) if @notice_processor
        when ParameterStatus
          @params[msg.key] = msg.value
        when BackendKeyData
          # TODO
          #p msg
        when ReadyForQuery
          # TODO: use transaction status
          pc,@pending_conn = @pending_conn,nil
          pc.succeed true
        else
          raise "unhandled message type"
        end
      end

      # Cloned and modified from the postgres-pr.
      def dispatch_query_message msg
        case msg
        when DataRow
          @r.rows << msg.columns
        when CommandComplete
          @r.cmd_tag = msg.cmd_tag
        when ReadyForQuery
          pq,@pending_query = @pending_query,nil
          pq.succeed true, @r, @e
        when RowDescription
          @r.fields = msg.fields
        when CopyInResponse
        when CopyOutResponse
        when EmptyQueryResponse
        when ErrorResponse
          # TODO
          @e << msg
        when NoticeResponse
          @notice_processor.call(msg) if @notice_processor
        else
          # TODO
        end
      end
    end
  end
end
