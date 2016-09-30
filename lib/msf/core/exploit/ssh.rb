module Msf
  module Exploit::Remote::SSH
    require 'rex/socket/ssh_factory'
    def ssh_socket_factory
      Rex::Socket::SSHFactory.new(framework, self, datastore['Proxies'])
    end
  end
end
