require 'uri'
require 'net/ssh/proxy/command'

module Net 
  module SSH 
    module Proxy

      # An implementation of a jump proxy. To use it, instantiate it,
      # then pass the instantiated object via the :proxy key to
      # Net::SSH.start:
      #
      #   require 'net/ssh/proxy/jump'
      #
      #   proxy = Net::SSH::Proxy::Jump.new('user@proxy')
      #   Net::SSH.start('host', 'user', :proxy => proxy) do |ssh|
      #     ...
      #   end
      class Jump < Command
        # The jump proxies
        attr_reader :jump_proxies
    
        # Create a new socket factory that tunnels via multiple jump proxes as
        # [user@]host[:port].
        def initialize(jump_proxies)
          @jump_proxies = jump_proxies
        end
    
        # Return a new socket connected to the given host and port via the jump
        # proxy that was requested when the socket factory was instantiated.
        def open(host, port, connection_options = nil)
          build_proxy_command_equivalent(connection_options)
          super
        end
    
        # We cannot build the ProxyCommand template until we know if the :config
        # option was specified during `Net::SSH.start`.
        def build_proxy_command_equivalent(connection_options = nil)
          first_jump, extra_jumps = jump_proxies.split(",", 2)
          config = connection_options && connection_options[:config]
          uri = URI.parse("ssh://#{first_jump}")
    
          template = "ssh"
          template << " -l #{uri.user}"    if uri.user
          template << " -p #{uri.port}"    if uri.port
          template << " -J #{extra_jumps}" if extra_jumps
          template << " -F #{config}" if config != true && config
          template << " -W %h:%p "
          template << uri.host
    
          @command_line_template = template
        end
      end

    end
  end
end
