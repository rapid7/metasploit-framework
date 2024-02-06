# -*- coding: binary -*-
#
# A mixin used for providing Modules with post-exploitation options and helper methods
#
module Msf::PostMixin

  include Msf::SessionCompatibility

  def initialize(info = {})
    super(
      update_info(
        info,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_config_sysinfo
            ]
          }
        }
      )
    )

    register_options( [
      Msf::OptInt.new('SESSION', [ true, 'The session to run this module on' ])
    ] , Msf::Post)
  end
end
