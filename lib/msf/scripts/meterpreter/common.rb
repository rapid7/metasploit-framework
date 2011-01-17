require 'msf/core/post/common'
require 'msf/core/post/windows/eventlog'
require 'msf/core/post/windows/priv'

module Msf
module Scripts
module Meterpreter
module Common

include Msf::Post::Priv
include Msf::Post::Eventlog
include Msf::Post::Common

end
end
end
end

