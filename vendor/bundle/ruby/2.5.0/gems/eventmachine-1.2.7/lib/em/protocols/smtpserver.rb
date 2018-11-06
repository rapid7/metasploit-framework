#--
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 16 July 2006
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

module EventMachine
  module Protocols

    # This is a protocol handler for the server side of SMTP.
    # It's NOT a complete SMTP server obeying all the semantics of servers conforming to
    # RFC2821. Rather, it uses overridable method stubs to communicate protocol states
    # and data to user code. User code is responsible for doing the right things with the
    # data in order to get complete and correct SMTP server behavior.
    #
    # Simple SMTP server example:
    #
    #  class EmailServer < EM::P::SmtpServer
    #    def receive_plain_auth(user, pass)
    #      true
    #    end
    #
    #    def get_server_domain
    #      "mock.smtp.server.local"
    #    end
    #
    #    def get_server_greeting
    #      "mock smtp server greets you with impunity"
    #    end
    #
    #    def receive_sender(sender)
    #      current.sender = sender
    #      true
    #    end
    #
    #    def receive_recipient(recipient)
    #      current.recipient = recipient
    #      true
    #    end
    #
    #    def receive_message
    #      current.received = true
    #      current.completed_at = Time.now
    #
    #      p [:received_email, current]
    #      @current = OpenStruct.new
    #      true
    #    end
    #
    #    def receive_ehlo_domain(domain)
    #      @ehlo_domain = domain
    #      true
    #    end
    #
    #    def receive_data_command
    #      current.data = ""
    #      true
    #    end
    #
    #    def receive_data_chunk(data)
    #      current.data << data.join("\n")
    #      true
    #    end
    #
    #    def receive_transaction
    #      if @ehlo_domain
    #        current.ehlo_domain = @ehlo_domain
    #        @ehlo_domain = nil
    #      end
    #      true
    #    end
    #
    #    def current
    #      @current ||= OpenStruct.new
    #    end
    #
    #    def self.start(host = 'localhost', port = 1025)
    #      require 'ostruct'
    #      @server = EM.start_server host, port, self
    #    end
    #
    #    def self.stop
    #      if @server
    #        EM.stop_server @server
    #        @server = nil
    #      end
    #    end
    #
    #    def self.running?
    #      !!@server
    #    end
    #  end
    #
    #  EM.run{ EmailServer.start }
    #
    #--
    # Useful paragraphs in RFC-2821:
    # 4.3.2: Concise list of command-reply sequences, in essence a text representation
    # of the command state-machine.
    #
    # STARTTLS is defined in RFC2487.
    # Observe that there are important rules governing whether a publicly-referenced server
    # (meaning one whose Internet address appears in public MX records) may require the
    # non-optional use of TLS.
    # Non-optional TLS does not apply to EHLO, NOOP, QUIT or STARTTLS.
    class SmtpServer < EventMachine::Connection
      include Protocols::LineText2

      HeloRegex = /\AHELO\s*/i
      EhloRegex = /\AEHLO\s*/i
      QuitRegex = /\AQUIT/i
      MailFromRegex = /\AMAIL FROM:\s*/i
      RcptToRegex = /\ARCPT TO:\s*/i
      DataRegex = /\ADATA/i
      NoopRegex = /\ANOOP/i
      RsetRegex = /\ARSET/i
      VrfyRegex = /\AVRFY\s+/i
      ExpnRegex = /\AEXPN\s+/i
      HelpRegex = /\AHELP/i
      StarttlsRegex = /\ASTARTTLS/i
      AuthRegex = /\AAUTH\s+/i


      # Class variable containing default parameters that can be overridden
      # in application code.
      # Individual objects of this class will make an instance-local copy of
      # the class variable, so that they can be reconfigured on a per-instance
      # basis.
      #
      # Chunksize is the number of data lines we'll buffer before
      # sending them to the application. TODO, make this user-configurable.
      #
      @@parms = {
        :chunksize => 4000,
        :verbose => false
      }
      def self.parms= parms={}
        @@parms.merge!(parms)
      end



      def initialize *args
        super
        @parms = @@parms
        init_protocol_state
      end

      def parms= parms={}
        @parms.merge!(parms)
      end

      # In SMTP, the server talks first. But by a (perhaps flawed) axiom in EM,
      # #post_init will execute BEFORE the block passed to #start_server, for any
      # given accepted connection. Since in this class we'll probably be getting
      # a lot of initialization parameters, we want the guts of post_init to
      # run AFTER the application has initialized the connection object. So we
      # use a spawn to schedule the post_init to run later.
      # It's a little weird, I admit. A reasonable alternative would be to set
      # parameters as a class variable and to do that before accepting any connections.
      #
      # OBSOLETE, now we have @@parms. But the spawn is nice to keep as an illustration.
      #
      def post_init
        #send_data "220 #{get_server_greeting}\r\n" (ORIGINAL)
        #(EM.spawn {|x| x.send_data "220 #{x.get_server_greeting}\r\n"}).notify(self)
        (EM.spawn {|x| x.send_server_greeting}).notify(self)
      end

      def send_server_greeting
        send_data "220 #{get_server_greeting}\r\n"
      end

      def receive_line ln
        @@parms[:verbose] and $>.puts ">>> #{ln}"

        return process_data_line(ln) if @state.include?(:data)
        return process_auth_line(ln) if @state.include?(:auth_incomplete)

        case ln
        when EhloRegex
          process_ehlo $'.dup
        when HeloRegex
          process_helo $'.dup
        when MailFromRegex
          process_mail_from $'.dup
        when RcptToRegex
          process_rcpt_to $'.dup
        when DataRegex
          process_data
        when RsetRegex
          process_rset
        when VrfyRegex
          process_vrfy
        when ExpnRegex
          process_expn
        when HelpRegex
          process_help
        when NoopRegex
          process_noop
        when QuitRegex
          process_quit
        when StarttlsRegex
          process_starttls
        when AuthRegex
          process_auth $'.dup
        else
          process_unknown
        end
      end
      
      # TODO - implement this properly, the implementation is a stub!
      def process_help
        send_data "250 Ok, but unimplemented\r\n"
      end
      
      # RFC2821, 3.5.3 Meaning of VRFY or EXPN Success Response:
      #   A server MUST NOT return a 250 code in response to a VRFY or EXPN
      #   command unless it has actually verified the address.  In particular,
      #   a server MUST NOT return 250 if all it has done is to verify that the
      #   syntax given is valid.  In that case, 502 (Command not implemented)
      #   or 500 (Syntax error, command unrecognized) SHOULD be returned.
      #
      # TODO - implement this properly, the implementation is a stub!
      def process_vrfy
        send_data "502 Command not implemented\r\n"
      end
      # TODO - implement this properly, the implementation is a stub!
      def process_expn
        send_data "502 Command not implemented\r\n"
      end

      #--
      # This is called at several points to restore the protocol state
      # to a pre-transaction state. In essence, we "forget" having seen
      # any valid command except EHLO and STARTTLS.
      # We also have to callback user code, in case they're keeping track
      # of senders, recipients, and whatnot.
      #
      # We try to follow the convention of avoiding the verb "receive" for
      # internal method names except receive_line (which we inherit), and
      # using only receive_xxx for user-overridable stubs.
      #
      # init_protocol_state is called when we initialize the connection as
      # well as during reset_protocol_state. It does NOT call the user
      # override method. This enables us to promise the users that they
      # won't see the overridable fire except after EHLO and RSET, and
      # after a message has been received. Although the latter may be wrong.
      # The standard may allow multiple DATA segments with the same set of
      # senders and recipients.
      #
      def reset_protocol_state
        init_protocol_state
        s,@state = @state,[]
        @state << :starttls if s.include?(:starttls)
        @state << :ehlo if s.include?(:ehlo)
        receive_transaction
      end
      def init_protocol_state
        @state ||= []
      end


      #--
      # EHLO/HELO is always legal, per the standard. On success
      # it always clears buffers and initiates a mail "transaction."
      # Which means that a MAIL FROM must follow.
      #
      # Per the standard, an EHLO/HELO or a RSET "initiates" an email
      # transaction. Thereafter, MAIL FROM must be received before
      # RCPT TO, before DATA. Not sure what this specific ordering
      # achieves semantically, but it does make it easier to
      # implement. We also support user-specified requirements for
      # STARTTLS and AUTH. We make it impossible to proceed to MAIL FROM
      # without fulfilling tls and/or auth, if the user specified either
      # or both as required. We need to check the extension standard
      # for auth to see if a credential is discarded after a RSET along
      # with all the rest of the state. We'll behave as if it is.
      # Now clearly, we can't discard tls after its been negotiated
      # without dropping the connection, so that flag doesn't get cleared.
      #
      def process_ehlo domain
        if receive_ehlo_domain domain
          send_data "250-#{get_server_domain}\r\n"
          if @@parms[:starttls]
            send_data "250-STARTTLS\r\n"
          end
          if @@parms[:auth]
            send_data "250-AUTH PLAIN\r\n"
          end
          send_data "250-NO-SOLICITING\r\n"
          # TODO, size needs to be configurable.
          send_data "250 SIZE 20000000\r\n"
          reset_protocol_state
          @state << :ehlo
        else
          send_data "550 Requested action not taken\r\n"
        end
      end

      def process_helo domain
        if receive_ehlo_domain domain.dup
          send_data "250 #{get_server_domain}\r\n"
          reset_protocol_state
          @state << :ehlo
        else
          send_data "550 Requested action not taken\r\n"
        end
      end

      def process_quit
        send_data "221 Ok\r\n"
        close_connection_after_writing
      end

      def process_noop
        send_data "250 Ok\r\n"
      end

      def process_unknown
        send_data "500 Unknown command\r\n"
      end

      #--
      # So far, only AUTH PLAIN is supported but we should do at least LOGIN as well.
      # TODO, support clients that send AUTH PLAIN with no parameter, expecting a 3xx
      # response and a continuation of the auth conversation.
      #
      def process_auth str
        if @state.include?(:auth)
          send_data "503 auth already issued\r\n"
        elsif str =~ /\APLAIN\s?/i
          if $'.length == 0
            # we got a partial response, so let the client know to send the rest
            @state << :auth_incomplete
            send_data("334 \r\n")
          else
            # we got the initial response, so go ahead & process it
            process_auth_line($')
          end
          #elsif str =~ /\ALOGIN\s+/i
        else
          send_data "504 auth mechanism not available\r\n"
        end
      end

      def process_auth_line(line)
        plain = line.unpack("m").first
        _,user,psw = plain.split("\000")
        
        succeeded = proc {
          send_data "235 authentication ok\r\n"
          @state << :auth
        }
        failed = proc {
          send_data "535 invalid authentication\r\n"
        }
        auth = receive_plain_auth user,psw
        
        if auth.respond_to?(:callback)
          auth.callback(&succeeded)
          auth.errback(&failed)
        else
          (auth ? succeeded : failed).call
        end
        
        @state.delete :auth_incomplete
      end

      #--
      # Unusually, we can deal with a Deferrable returned from the user application.
      # This was added to deal with a special case in a particular application, but
      # it would be a nice idea to add it to the other user-code callbacks.
      #
      def process_data
        unless @state.include?(:rcpt)
          send_data "503 Operation sequence error\r\n"
        else
          succeeded = proc {
            send_data "354 Send it\r\n"
            @state << :data
            @databuffer = []
          }
          failed = proc {
            send_data "550 Operation failed\r\n"
          }

          d = receive_data_command

          if d.respond_to?(:callback)
            d.callback(&succeeded)
            d.errback(&failed)
          else
            (d ? succeeded : failed).call
          end
        end
      end

      def process_rset
        reset_protocol_state
        receive_reset
        send_data "250 Ok\r\n"
      end

      def unbind
        connection_ended
      end

      #--
      # STARTTLS may not be issued before EHLO, or unless the user has chosen
      # to support it.
      #
      # If :starttls_options is present and :starttls is set in the parms
      # pass the options in :starttls_options to start_tls. Do this if you want to use
      # your own certificate
      # e.g. {:cert_chain_file => "/etc/ssl/cert.pem", :private_key_file => "/etc/ssl/private/cert.key"}

      def process_starttls
        if @@parms[:starttls]
          if @state.include?(:starttls)
            send_data "503 TLS Already negotiated\r\n"
          elsif ! @state.include?(:ehlo)
            send_data "503 EHLO required before STARTTLS\r\n"
          else
            send_data "220 Start TLS negotiation\r\n"
            start_tls(@@parms[:starttls_options] || {})
            @state << :starttls
          end
        else
          process_unknown
        end
      end


      #--
      # Requiring TLS is touchy, cf RFC2784.
      # Requiring AUTH seems to be much more reasonable.
      # We don't currently support any notion of deriving an authentication from the TLS
      # negotiation, although that would certainly be reasonable.
      # We DON'T allow MAIL FROM to be given twice.
      # We DON'T enforce all the various rules for validating the sender or
      # the reverse-path (like whether it should be null), and notifying the reverse
      # path in case of delivery problems. All of that is left to the calling application.
      #
      def process_mail_from sender
        if (@@parms[:starttls]==:required and !@state.include?(:starttls))
          send_data "550 This server requires STARTTLS before MAIL FROM\r\n"
        elsif (@@parms[:auth]==:required and !@state.include?(:auth))
          send_data "550 This server requires authentication before MAIL FROM\r\n"
        elsif @state.include?(:mail_from)
          send_data "503 MAIL already given\r\n"
        else
          unless receive_sender sender
            send_data "550 sender is unacceptable\r\n"
          else
            send_data "250 Ok\r\n"
            @state << :mail_from
          end
        end
      end

      #--
      # Since we require :mail_from to have been seen before we process RCPT TO,
      # we don't need to repeat the tests for TLS and AUTH.
      # Note that we don't remember or do anything else with the recipients.
      # All of that is on the user code.
      # TODO: we should enforce user-definable limits on the total number of
      # recipients per transaction.
      # We might want to make sure that a given recipient is only seen once, but
      # for now we'll let that be the user's problem.
      #
      # User-written code can return a deferrable from receive_recipient.
      #
      def process_rcpt_to rcpt
        unless @state.include?(:mail_from)
          send_data "503 MAIL is required before RCPT\r\n"
        else
          succeeded = proc {
            send_data "250 Ok\r\n"
            @state << :rcpt unless @state.include?(:rcpt)
          }
          failed = proc {
            send_data "550 recipient is unacceptable\r\n"
          }

          d = receive_recipient rcpt

          if d.respond_to?(:set_deferred_status)
            d.callback(&succeeded)
            d.errback(&failed)
          else
            (d ? succeeded : failed).call
          end

=begin
        unless receive_recipient rcpt
          send_data "550 recipient is unacceptable\r\n"
        else
          send_data "250 Ok\r\n"
          @state << :rcpt unless @state.include?(:rcpt)
        end
=end
        end
      end


      # Send the incoming data to the application one chunk at a time, rather than
      # one line at a time. That lets the application be a little more flexible about
      # storing to disk, etc.
      # Since we clear the chunk array every time we submit it, the caller needs to be
      # aware to do things like dup it if he wants to keep it around across calls.
      #
      # Resets the transaction upon disposition of the incoming message.
      # RFC5321 says this about the MAIL FROM command:
      #  "This command tells the SMTP-receiver that a new mail transaction is
      #   starting and to reset all its state tables and buffers, including any
      #   recipients or mail data."
      #
      # Equivalent behaviour is implemented by resetting after a completed transaction.
      #
      # User-written code can return a Deferrable as a response from receive_message.
      #
      def process_data_line ln
        if ln == "."
          if @databuffer.length > 0
            receive_data_chunk @databuffer
            @databuffer.clear
          end


          succeeded = proc {
            send_data "250 Message accepted\r\n"
            reset_protocol_state
          }
          failed = proc {
            send_data "550 Message rejected\r\n"
            reset_protocol_state
          }
          d = receive_message

          if d.respond_to?(:set_deferred_status)
            d.callback(&succeeded)
            d.errback(&failed)
          else
            (d ? succeeded : failed).call
          end

          @state.delete :data
        else
          # slice off leading . if any
          ln.slice!(0...1) if ln[0] == ?.
          @databuffer << ln
          if @databuffer.length > @@parms[:chunksize]
            receive_data_chunk @databuffer
            @databuffer.clear
          end
        end
      end


      #------------------------------------------
      # Everything from here on can be overridden in user code.

      # The greeting returned in the initial connection message to the client.
      def get_server_greeting
        "EventMachine SMTP Server"
      end
      # The domain name returned in the first line of the response to a
      # successful EHLO or HELO command.
      def get_server_domain
        "Ok EventMachine SMTP Server"
      end

      # A false response from this user-overridable method will cause a
      # 550 error to be returned to the remote client.
      #
      def receive_ehlo_domain domain
        true
      end

      # Return true or false to indicate that the authentication is acceptable.
      def receive_plain_auth user, password
        true
      end

      # Receives the argument of the MAIL FROM command. Return false to
      # indicate to the remote client that the sender is not accepted.
      # This can only be successfully called once per transaction.
      #
      def receive_sender sender
        true
      end

      # Receives the argument of a RCPT TO command. Can be given multiple
      # times per transaction. Return false to reject the recipient.
      #
      def receive_recipient rcpt
        true
      end

      # Sent when the remote peer issues the RSET command.
      # Since RSET is not allowed to fail (according to the protocol),
      # we ignore any return value from user overrides of this method.
      #
      def receive_reset
      end

      # Sent when the remote peer has ended the connection.
      #
      def connection_ended
      end

      # Called when the remote peer sends the DATA command.
      # Returning false will cause us to send a 550 error to the peer.
      # This can be useful for dealing with problems that arise from processing
      # the whole set of sender and recipients.
      #
      def receive_data_command
        true
      end

      # Sent when data from the remote peer is available. The size can be controlled
      # by setting the :chunksize parameter. This call can be made multiple times.
      # The goal is to strike a balance between sending the data to the application one
      # line at a time, and holding all of a very large message in memory.
      #
      def receive_data_chunk data
        @smtps_msg_size ||= 0
        @smtps_msg_size += data.join.length
        STDERR.write "<#{@smtps_msg_size}>"
      end

      # Sent after a message has been completely received. User code
      # must return true or false to indicate whether the message has
      # been accepted for delivery.
      def receive_message
        @@parms[:verbose] and $>.puts "Received complete message"
        true
      end

      # This is called when the protocol state is reset. It happens
      # when the remote client calls EHLO/HELO or RSET.
      def receive_transaction
      end
    end
  end
end
