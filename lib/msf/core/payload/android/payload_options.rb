# -*- coding: binary -*-

require 'msf/core'

module Msf::Payload::Android::PayloadOptions

  def initialize(info = {})
    super(info)
    register_advanced_options(
      [
        Msf::OptBool.new('AndroidMeterpreterDebug', [ false, "Run the payload in debug mode, with logging enabled" ]),
        Msf::OptBool.new('AndroidWakelock', [ false, "Acquire a wakelock before starting the payload", true ]),
        Msf::OptBool.new('AndroidHideAppIcon', [ false, "Hide the application icon automatically after launch" ]),
      ]
    )
  end

end
