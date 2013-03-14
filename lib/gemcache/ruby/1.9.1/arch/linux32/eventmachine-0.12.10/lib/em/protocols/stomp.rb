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

    # Implements Stomp (http://docs.codehaus.org/display/STOMP/Protocol).
    #
    # == Usage example
    #
    #  module StompClient
    #    include EM::Protocols::Stomp
    #
    #    def connection_completed
    #      connect :login => 'guest', :passcode => 'guest'
    #    end
    #
    #    def receive_msg msg
    #      if msg.command == "CONNECTED"
    #        subscribe '/some/topic'
    #      else
    #        p ['got a message', msg]
    #        puts msg.body
    #      end
    #    end
    #  end
    #
    #  EM.run{
    #    EM.connect 'localhost', 61613, StompClient
    #  }
    #
    module Stomp
      include LineText2

      class Message
        # The command associated with the message, usually 'CONNECTED' or 'MESSAGE'
        attr_accessor :command
        # Hash containing headers such as destination and message-id
        attr_accessor :header
        alias :headers :header
        # Body of the message
        attr_accessor :body

        def initialize # :nodoc:
          @header = {}
          @state = :precommand
          @content_length = nil
        end
        def consume_line line # :nodoc:
          if @state == :precommand
            unless line =~ /\A\s*\Z/
              @command = line
              @state = :headers
            end
          elsif @state == :headers
            if line == ""
              if @content_length
                yield( [:sized_text, @content_length+1] )
              else
                @state = :body
                yield( [:unsized_text] )
              end
            elsif line =~ /\A([^:]+):(.+)\Z/
              k = $1.dup.strip
              v = $2.dup.strip
              @header[k] = v
              if k == "content-length"
                @content_length = v.to_i
              end
            else
              # This is a protocol error. How to signal it?
            end
          elsif @state == :body
            @body = line
            yield( [:dispatch] )
          end
        end
      end

      # :stopdoc:

      def send_frame verb, headers={}, body=""
        ary = [verb, "\n"]
        headers.each {|k,v| ary << "#{k}:#{v}\n" }
        ary << "content-length: #{body.to_s.length}\n"
        ary << "content-type: text/plain; charset=UTF-8\n"
        ary << "\n"
        ary << body.to_s
        ary << "\0"
        send_data ary.join
      end

      def receive_line line
        @stomp_initialized || init_message_reader
        @stomp_message.consume_line(line) {|outcome|
          if outcome.first == :sized_text
            set_text_mode outcome[1]
          elsif outcome.first == :unsized_text
            set_delimiter "\0"
          elsif outcome.first == :dispatch
            receive_msg(@stomp_message) if respond_to?(:receive_msg)
            init_message_reader
          end
        }
      end

      def receive_binary_data data
        @stomp_message.body = data[0..-2]
        receive_msg(@stomp_message) if respond_to?(:receive_msg)
        init_message_reader
      end

      def init_message_reader
        @stomp_initialized = true
        set_delimiter "\n"
        set_line_mode
        @stomp_message = Message.new
      end

      # :startdoc:

      # Invoked with an incoming Stomp::Message received from the STOMP server
      def receive_msg msg
        # stub, overwrite this in your handler
      end

      # CONNECT command, for authentication
      #
      #  connect :login => 'guest', :passcode => 'guest'
      #
      def connect parms={}
        send_frame "CONNECT", parms
      end

      # SEND command, for publishing messages to a topic
      #
      #  send '/topic/name', 'some message here'
      #
      def send destination, body, parms={}
        send_frame "SEND", parms.merge( :destination=>destination ), body.to_s
      end

      # SUBSCRIBE command, for subscribing to topics
      #
      #  subscribe '/topic/name', false
      #
      def subscribe dest, ack=false
        send_frame "SUBSCRIBE", {:destination=>dest, :ack=>(ack ? "client" : "auto")}
      end

      # ACK command, for acknowledging receipt of messages
      #
      #  module StompClient
      #    include EM::P::Stomp
      #
      #    def connection_completed
      #      connect :login => 'guest', :passcode => 'guest'
      #      # subscribe with ack mode
      #      subscribe '/some/topic', true
      #    end
      #
      #    def receive_msg msg
      #      if msg.command == "MESSAGE"
      #        ack msg.headers['message-id']
      #        puts msg.body
      #      end
      #    end
      #  end
      #
      def ack msgid
        send_frame "ACK", 'message-id'=> msgid
      end

    end
  end
end

