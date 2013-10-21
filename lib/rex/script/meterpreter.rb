# -*- coding: binary -*-

module Rex
module Script
class Meterpreter < Base

begin
  require 'msf/scripts/meterpreter'
  include Msf::Scripts::Meterpreter::Common
rescue ::LoadError
end

end
end
end

