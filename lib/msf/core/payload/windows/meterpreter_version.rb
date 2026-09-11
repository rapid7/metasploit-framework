# -*- coding: binary -*-

module Msf

module Payload::Windows::MeterpreterVersion
  # The minimum version of Windows that is able to run Meterpreter payloads. Versions below this are not supported.
  MINIMUM_VERSION = Msf::WindowsVersion::XP_SP2
end

end
