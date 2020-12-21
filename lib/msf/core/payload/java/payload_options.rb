# -*- coding: binary -*-

require 'msf/core'

module Msf::Payload::Java::PayloadOptions

  def initialize(info = {})
    super(info)
    register_advanced_options(
      [
        Msf::OptBool.new('JavaMeterpreterDebug', [ false, "Run the payload in debug mode, with logging enabled" ]),
        Msf::OptInt.new('Spawn', [true, "Number of subprocesses to spawn", 2])
      ]
    )
  end

  #
  # Generate default configuration that is to be included in the stager.
  #
  def stager_config(opts={})
    ds = opts[:datastore] || datastore
    spawn = ds["Spawn"] || 2
    c =  ""
    if ds["JavaMeterpreterDebug"]
      spawn = 0
      c << "StageParameters=NoRedirect\n"
    end
    c << "Spawn=#{spawn}\n"
    c
  end

end
