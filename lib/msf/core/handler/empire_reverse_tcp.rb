# -*- coding: binary -*-
require 'rex/socket'
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
            OptString.new(
              'ListenerName',
              [true,'Name of the listener the Empire payload is made for']),
            OptString.new(
              'PathToEmpire',
              [true,'Path to the directory where Empire is installed'])
          ])
        deregister_options('LHOST','LPORT')
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
          #Storing user inputs
          @path = datastore['PathToEmpire'].to_s
          @listener_name = datastore['ListenerName']

          #check for open port at 1337
          command = "netstat -nlt | grep 1337"
          value = system(value)
          raise "Port 1337 is already in use." if value
        end

        #Empire Rest-API method
        def initiate_API
          sleep(7)
          Dir.chdir(path)
          command = "./empire --headless --username 'msf-empire' --password 'msf-empire' > /dev/null"
          value = system(command)

          #Creating an Empire instance
          @client_emp = Msf::Empire::Client.new('msf-empire','msf-empire')

          #Check if the listener name provided is valid
          response = @client_emp.is_listener_active(@listener_name)
          raise response.to_s if not response.to_s.include?('active')
          puts response
        end

        #Method to listen for inbound connenctions
        def handle_sessions
          #Retrieving connected agents at an interval of 6 seconds
          sleep(15)
          @agent_name = @client_emp.get_agents(true)
          empire_session = Msf::Sessions::EmpireShellWindows.new(@client_emp, @agent_name)
          framework.sessions.register(empire_sessions)
        end

        #Initiating the threads
        thread_main = Thread.new{
          main()
        }
        thread_api = Thread.new{
          initiate_API()
        }
        thread_sessions = Thread.new{
          handler_sessions()
        }

        #Joining the api thread
        thread_api.join
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

