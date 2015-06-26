# -*- coding: binary -*-

module Rex
module Script
class meeterpeter < Base

begin
  require 'msf/scripts/meeterpeter'
  include Msf::Scripts::meeterpeter::Common
rescue ::LoadError
end

end
end
end

