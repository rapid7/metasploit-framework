# -*- coding: binary -*-
require 'socket'
require 'resolv-replace'
require 'thread'
require 'msf/core/empire_lib'
require 'msf/base/sessions/empire.rb'

module Msf
  module Handler
    module EmpireReverseTcp
      include Msf::Handler
      include Msf::Handler::Reverse
      include Msf::Handler::Reverse::Comm

      #
      # Returns the string representation of the handler type, in this case
      # 'reverse_tcp'.
      #
      def self.handler_type
        "reverse_tcp"
      end

      #
      # Returns the connection-described general handler type, in this case
      # 'reverse'.
      #
      def self.general_handler_type
        "reverse"
      end

      #
      # Initializes the reverse TCP handler and ads the options that are required
      # for all reverse TCP payloads, like local host and local port.
      #
      def initialize(info = {})
        super
        #Registering Empire Options
        register_options(
          [
            OptAddress.new(
              'LHOST',
              [true, 'Local address to listen on.']),
            OptPort.new(
              'LPORT',
              [true,'Local port to listen on for inbound connections']),
            OptString.new(
              'ListenerName',
              [false,'Name of the listener the Empire payload is made for, if you remember.'])
          ])
      end

      # A string suitable for displaying to the user
      #
      # @return [String]
      def human_name
        "reverse TCP"
      end

      #
      # Starts monitoring for an inbound connection.
      #
      def start_handler
        #Defing thread methods for the handler
        #Main handler method
        def main
          def validate(lhost, lport)
            #Validating user inputs
            #LPORT
            ip = Socket.ip_address_list.detect{|intf| intf.ipv4_private?}
            if lhost != ip.ip_address
              raise "Invalid Local address. Please check your local IP."
            end
            #LPORT
            if system("netstat -nlt | grep #{lport} >> /dev/null")
              raise "Port #{lport} is already in use."
            end
          end
          #Storing user inputs
          @agentsConnected = {}
          @agentsLogged = []
          @host = datastore['LHOST']
          @port = datastore['LPORT']
          @listener_name = datastore['ListenerName']
          #
          #Validate environment to check if Empire is running at 1337
          #
          raise "No Empire instance found. Please initiate Empire at 1337 before starting MSF" if not system("netstat -nlt | grep 1337 >> /dev/null")
          #
          #Creating an Empire Instance
          #
          @client_emp = Msf::Empire::Client.new
          #
          #Continue directly to listen if the listener name mentioned is
          #already up and running, else start another listener with listener
          #name (if provided) or a random listener name
          #
          if not @listener_name.empty?
            response = @client_emp.is_listener_active(@listener_name)
            if response.to_s == false
              print_error("Listener name provided not found. Trying to create one.")
              validate(@host, @port)
              responseListener = @client_emp.create_listener(@listener_name, @host, @port)
              if responseListener.to_s.include?("Failed")
                raise(responseListener.to_s)
              else
                print_status(responseListener.to_s)
              end
            else
              print_status(response.to_s)
            end
          else
            @listener_name = "ListenerEmpire#{rand(1..100)}"
            validate(@host, @port)
            responseListener = @client_emp.create_listener(@listener_name, @host, @port)
            if responseListener.to_s.include?("Failed")
              raise(responseListener.to_s)
            else
              print_status(responseListener.to_s)
            end
          end


        end

        #Method to listen for inbound connenctions
        def handle_sessions
          sleep(10)
          #Retrieving connected agents at an interval of 6 seconds
          while (true)
            sleep(6)
            staticCount = 0
            @agentsConnected = @client_emp.get_agents()
            @agentsConnected.each do |listener, session_id|
              if listener == @listener_name
                @agentsLogged.each do |agents|
                  if session_id == agents
                    staticCount = staticCount + 1
                  end
                end
                if staticCount == 0
                  empireSession = Msf::Sessions::EmpireShellWindows.new(@client_emp, session_id)
                  framework.sessions.register(empireSession)
                  @agentsLogged.push(session_id)
                end
                staticCount = 0
              end
            end
          end
        end

        #Initiating the threads
        thread_main = Thread.new{
          main()
        }
        thread_sessions = Thread.new{
          handler_sessions()
        }

        #Joining the api thread
        thread_sessions.join
      end

      #
      # Stops monitoring for an inbound connection.
      #
      def stop_handler
        @client_emp.shutdown()
      end

      #
      # Closes the listener socket if one was created.
      #
      def cleanup_handler
        command = "kill 9 $(lsof -t i:1337)"
        value = system(command)
        if value
          print_status ("Handler Successfully Stopped")
        end
      end
    end
  end
end

