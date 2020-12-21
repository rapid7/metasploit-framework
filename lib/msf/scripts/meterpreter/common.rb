# -*- coding: binary -*-
require 'msf/core/post/common'
require 'msf/core/post/windows/eventlog'
require 'msf/core/post/windows/priv'

module Msf
module Scripts
module Meterpreter
module Common

include Msf::Post::Windows::Priv
include Msf::Post::Windows::Eventlog
include Msf::Post::Common

end
end
end
end

