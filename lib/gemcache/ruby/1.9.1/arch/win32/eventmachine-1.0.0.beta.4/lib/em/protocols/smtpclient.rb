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

require 'ostruct'

module EventMachine
  module Protocols

    # Simple SMTP client
    #
    # @example
    #   email = EM::Protocols::SmtpClient.send(
    #     :domain=>"example.com",
    #     :host=>'localhost',
    #     :port=>25, # optional, defaults 25
    #     :starttls=>true, # use ssl
    #     :from=>"sender@example.com",
    #     :to=> ["to_1@example.com", "to_2@example.com"],
    #     :header=> {"Subject" => "This is a subject line"},
    #     :body=> "This is the body of the email"
    #   )
    #   email.callback{
    #     puts 'Email sent!'
    #   }
    #   email.errback{ |e|
    #     puts 'Email failed!'
    #   }
    #
    # Sending generated emails (using mailfactory)
    #
    #   mail = MailFactory.new
    #   mail.to = 'someone@site.co'
    #   mail.from = 'me@site.com'
    #   mail.subject = 'hi!'
    #   mail.text = 'hello world'
    #   mail.html = '<h1>hello world</h1>'
    #
    #   email = EM::P::SmtpClient.send(
    #     :domain=>'site.com',
    #     :from=>mail.from,
    #     :to=>mail.to,
    #     :content=>"#{mail.to_s}\r\n.\r\n"
    #   )
    #
    class SmtpClient < Connection
      include EventMachine::Deferrable
      include EventMachine::Protocols::LineText2

      def initialize
        @succeeded = nil
        @responder = nil
        @code = nil
        @msg = nil
      end

      # :host => required String
      #   a string containing the IP address or host name of the SMTP server to connect to.
      # :port => optional
      #   defaults to 25.
      # :domain => required String
      #   This is passed as the argument to the EHLO command.
      # :starttls => optional Boolean
      #   If it evaluates true, then the client will initiate STARTTLS with
      #   the server, and abort the connection if the negotiation doesn't succeed.
      #   TODO, need to be able to pass certificate parameters with this option.
      # :auth => optional Hash of auth parameters
      #   If not given, then no auth will be attempted.
      #   (In that case, the connection will be aborted if the server requires auth.)
      #   Specify the hash value :type to determine the auth type, along with additional parameters
      #   depending on the type.
      #   Currently only :type => :plain is supported. Pass additional parameters :username (String),
      #   and :password (either a String or a Proc that will be called at auth-time).
      #
      #   @example
      #     :auth => {:type=>:plain, :username=>"mickey@disney.com", :password=>"mouse"}
      #
      # :from => required String
      #   Specifies the sender of the message. Will be passed as the argument
      #   to the MAIL FROM. Do NOT enclose the argument in angle-bracket (<>) characters.
      #   The connection will abort if the server rejects the value.
      # :to => required String or Array of Strings
      #   The recipient(s) of the message. Do NOT enclose
      #   any of the values in angle-brackets (<>) characters. It's NOT a fatal error if one or more
      #   recipients are rejected by the server. (Of course, if ALL of them are, the server will most
      #   likely trigger an error when we try to send data.) An array of codes containing the status
      #   of each requested recipient is available after the call completes. TODO, we should define
      #   an overridable stub that will be called on rejection of a recipient or a sender, giving
      #   user code the chance to try again or abort the connection.
      # :header => Required hash of values to be transmitted in the header of the message.
      #   The hash keys are the names of the headers (do NOT append a trailing colon), and the values are strings
      #   containing the header values. TODO, support Arrays of header values, which would cause us to
      #   send that specific header line more than once.
      #
      #   @example
      #     :header => {"Subject" => "Bogus", "CC" => "myboss@example.com"}
      #
      # :body => Optional string, defaults blank.
      #   This will be passed as the body of the email message.
      #   TODO, this needs to be significantly beefed up. As currently written, this requires the caller
      #   to properly format the input into CRLF-delimited lines of 7-bit characters in the standard
      #   SMTP transmission format. We need to be able to automatically convert binary data, and add
      #   correct line-breaks to text data. I think the :body parameter should remain as it is, and we
      #   should add a :content parameter that contains autoconversions and/or conversion parameters.
      #   Then we can check if either :body or :content is present and do the right thing.
      # :content => Optional array or string
      #   Alternative to providing header and body, an array or string of raw data which MUST be in
      #   correct SMTP body format, including a trailing dot line
      # :verbose => Optional.
      #   If true, will cause a lot of information (including the server-side of the
      #   conversation) to be dumped to $>.
      #
      def self.send args={}
        args[:port] ||= 25
        args[:body] ||= ""

=begin
      (I don't think it's possible for EM#connect to throw an exception under normal
      circumstances, so this original code is stubbed out. A connect-failure will result
      in the #unbind method being called without calling #connection_completed.)
      begin
        EventMachine.connect( args[:host], args[:port], self) {|c|
          # According to the EM docs, we will get here AFTER post_init is called.
          c.args = args
          c.set_comm_inactivity_timeout 60
        }
      rescue
        # We'll get here on a connect error. This code mimics the effect
        # of a call to invoke_internal_error. Would be great to DRY this up.
        # (Actually, it may be that we never get here, if EM#connect catches
        # its errors internally.)
        d = EM::DefaultDeferrable.new
        d.set_deferred_status(:failed, {:error=>[:connect, 500, "unable to connect to server"]})
        d
      end
=end
        EventMachine.connect( args[:host], args[:port], self) {|c|
          # According to the EM docs, we will get here AFTER post_init is called.
          c.args = args
          c.set_comm_inactivity_timeout 60
        }
      end

      attr_writer :args

      # @private
      def post_init
        @return_values = OpenStruct.new
        @return_values.start_time = Time.now
      end

      # @private
      def connection_completed
        @responder = :receive_signon
        @msg = []
      end

      # We can get here in a variety of ways, all of them being failures unless
      # the @succeeded flag is set. If a protocol success was recorded, then don't
      # set a deferred success because the caller will already have done it
      # (no need to wait until the connection closes to invoke the callbacks).
      #
      # @private
      def unbind
        unless @succeeded
          @return_values.elapsed_time = Time.now - @return_values.start_time
          @return_values.responder = @responder
          @return_values.code = @code
          @return_values.message = @msg
          set_deferred_status(:failed, @return_values)
        end
      end

      # @private
      def receive_line ln
        $>.puts ln if @args[:verbose]
        @range = ln[0...1].to_i
        @code = ln[0...3].to_i
        @msg << ln[4..-1]
        unless ln[3...4] == '-'
          $>.puts @responder if @args[:verbose]
          send @responder
          @msg.clear
        end
      end

      private

      # We encountered an error from the server and will close the connection.
      # Use the error and message the server returned.
      #
      def invoke_error
        @return_values.elapsed_time = Time.now - @return_values.start_time
        @return_values.responder = @responder
        @return_values.code = @code
        @return_values.message = @msg
        set_deferred_status :failed, @return_values
        send_data "QUIT\r\n"
        close_connection_after_writing
      end

      # We encountered an error on our side of the protocol and will close the connection.
      # Use an extra-protocol error code (900) and use the message from the caller.
      #
      def invoke_internal_error msg = "???"
        @return_values.elapsed_time = Time.now - @return_values.start_time
        @return_values.responder = @responder
        @return_values.code = 900
        @return_values.message = msg
        set_deferred_status :failed, @return_values
        send_data "QUIT\r\n"
        close_connection_after_writing
      end

      def receive_signon
        return invoke_error unless @range == 2
        send_data "EHLO #{@args[:domain]}\r\n"
        @responder = :receive_ehlo_response
      end

      def receive_ehlo_response
        return invoke_error unless @range == 2
        @server_caps = @msg
        invoke_starttls
      end

      def invoke_starttls
        if @args[:starttls]
          # It would be more sociable to first ask if @server_caps contains
          # the string "STARTTLS" before we invoke it, but hey, life's too short.
          send_data "STARTTLS\r\n"
          @responder = :receive_starttls_response
        else
          invoke_auth
        end
      end
      def receive_starttls_response
        return invoke_error unless @range == 2
        start_tls
        invoke_auth
      end

      # Perform an authentication. If the caller didn't request one, then fall through
      # to the mail-from state.
      def invoke_auth
        if @args[:auth]
          if @args[:auth][:type] == :plain
            psw = @args[:auth][:password]
            if psw.respond_to?(:call)
              psw = psw.call
            end
            #str = Base64::encode64("\0#{@args[:auth][:username]}\0#{psw}").chomp
            str = ["\0#{@args[:auth][:username]}\0#{psw}"].pack("m").chomp
            send_data "AUTH PLAIN #{str}\r\n"
            @responder = :receive_auth_response
          else
            return invoke_internal_error("unsupported auth type")
          end
        else
          invoke_mail_from
        end
      end
      def receive_auth_response
        return invoke_error unless @range == 2
        invoke_mail_from
      end

      def invoke_mail_from
        send_data "MAIL FROM: <#{@args[:from]}>\r\n"
        @responder = :receive_mail_from_response
      end
      def receive_mail_from_response
        return invoke_error unless @range == 2
        invoke_rcpt_to
      end

      def invoke_rcpt_to
        @rcpt_responses ||= []
        l = @rcpt_responses.length
        to = @args[:to].is_a?(Array) ? @args[:to] : [@args[:to].to_s]
        if l < to.length
          send_data "RCPT TO: <#{to[l]}>\r\n"
          @responder = :receive_rcpt_to_response
        else
          e = @rcpt_responses.select {|rr| rr.last == 2}
          if e and e.length > 0
            invoke_data
          else
            invoke_error
          end
        end
      end
      def receive_rcpt_to_response
        @rcpt_responses << [@code, @msg, @range]
        invoke_rcpt_to
      end

      def invoke_data
        send_data "DATA\r\n"
        @responder = :receive_data_response
      end
      def receive_data_response
        return invoke_error unless @range == 3

        # The data to send can be given either in @args[:content] (an array or string of raw data
        # which MUST be in correct SMTP body format, including a trailing dot line), or a header and
        # body given in @args[:header] and @args[:body].
        #
        if @args[:content]
          send_data @args[:content].to_s
        else
          # The header can be a hash or an array.
          if @args[:header].is_a?(Hash)
            (@args[:header] || {}).each {|k,v| send_data "#{k}: #{v}\r\n" }
          else
            send_data @args[:header].to_s
          end
          send_data "\r\n"

          if @args[:body].is_a?(Array)
            @args[:body].each {|e| send_data e}
          else
            send_data @args[:body].to_s
          end

          send_data "\r\n.\r\n"
        end

        @responder = :receive_message_response
      end
      def receive_message_response
        return invoke_error unless @range == 2
        send_data "QUIT\r\n"
        close_connection_after_writing
        @succeeded = true
        @return_values.elapsed_time = Time.now - @return_values.start_time
        @return_values.responder = @responder
        @return_values.code = @code
        @return_values.message = @msg
        set_deferred_status :succeeded, @return_values
      end
    end
  end
end
