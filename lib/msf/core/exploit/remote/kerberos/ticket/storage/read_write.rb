module Msf::Exploit::Remote::Kerberos::Ticket::Storage
  class ReadWrite < Base
    include ReadMixin
    include WriteMixin
  end
end
