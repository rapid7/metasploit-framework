# -*- coding: binary -*-
module Msf
module Scripts
module Meterpreter
module Common

include Msf::Post::Windows::Priv
include Msf::Post::Windows::Eventlog
include Msf::Post::Common
include ::Msf::Post::Windows::Registry
include ::Msf::Post::File
include ::Msf::Post::Windows::Services
include ::Msf::Post::Windows::Accounts

end
end
end
end

