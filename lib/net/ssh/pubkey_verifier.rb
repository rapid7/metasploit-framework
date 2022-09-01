require 'net/ssh'

module Net
  module SSH

    class PubkeyVerifier
      include Net::SSH::Transport::Constants
      include Net::SSH::Authentication::Constants

      attr_accessor :connection, :host, :key, :options, :user

      def initialize(host,user, opts)
        @host = host
        # Parse public key data out into a PKey object
        pubkey_data = opts.fetch(:key_data)
        @key = Net::SSH::KeyFactory.load_data_public_key(pubkey_data)
        @user = user

        # Always set auth methods to ONLY publickey regardless
        # of what the user sends
        opts[:auth_methods] = ['publickey']
        @options = Net::SSH.configuration_for(host, opts.fetch(:config, true)).merge(opts)
      end

      def auth_session(transport)
        Net::SSH::Authentication::Session.new(transport,options)
      end

      def ssh_transport
        Net::SSH::Transport::Session.new(host,options)
      end

      def verify
        transport = ssh_transport
        auth      = auth_session(transport)

        transport.send_message(transport.service_request("ssh-userauth"))
        auth.expect_message(SERVICE_ACCEPT)

        # The initial public key exchange
        pubkey_method = Net::SSH::Authentication::Methods::Publickey.new(auth)
        pubkey_method.send(:send_request, key,user, "ssh-connection")

        # Check the response to see if the public key is good
        response_message = auth.next_message
        case response_message.type
          when USERAUTH_PK_OK
            @connection = Net::SSH::Connection::Session.new(transport, options)
            true
          when USERAUTH_FAILURE
            false
          else
            raise Net::SSH::Exception, "unexpected reply to USERAUTH_REQUEST: #{response_message.type} (#{response_message.inspect})"
        end
      end


    end
  end
end
