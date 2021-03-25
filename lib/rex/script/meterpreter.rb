# -*- coding: binary -*-

module Rex
module Script
class Meterpreter < Base

begin
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Eventlog
  include Msf::Post::Common
  include Msf::Post::Windows::Registry
  include Msf::Post::File
  include Msf::Post::Windows::Services
  include Msf::Post::Windows::Accounts
rescue ::LoadError
end

end
end
end

