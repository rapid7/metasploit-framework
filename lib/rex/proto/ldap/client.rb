require 'net/ldap'

module Rex
  module Proto
    module LDAP
      # This is a Rex Proto wrapper around the Net::LDAP client which is currently coming from the 'net-ldap' gem.
      # The purpose of this wrapper is to provide 'peerhost' and 'peerport' methods to ensure the client interfaces
      # are consistent between various session clients.
      class Client < Net::LDAP

        # @return [Rex::Socket]
        attr_reader :socket

        # [Time] The last time an interaction occurred on the connection (for keep-alive purposes)
        attr_reader :last_interaction

        # [Mutex] Control access to the connection. One at a time.
        attr_reader :connection_use_mutex

        def initialize(args)
          @base_dn = args[:base]
          @last_interaction = nil
          @connection_use_mutex = Mutex.new
          super
        end

        def register_interaction
          @last_interaction = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end

        # @return [Array<String>] LDAP servers naming contexts
        def naming_contexts
          @naming_contexts ||= search_root_dse[:namingcontexts]
        end

        # @return [String] LDAP servers Base DN
        def base_dn
          @base_dn ||= discover_base_dn
        end

        # @return [String, nil] LDAP servers Schema DN, nil if one isn't found
        def schema_dn
          @schema_dn ||= discover_schema_naming_context
        end

        # @return [String] The remote IP address that LDAP is running on
        def peerhost
          host
        end

        # @return [Integer] The remote port that LDAP is running on
        def peerport
          port
        end

        # @return [String] The remote peer information containing IP and port
        def peerinfo
          "#{peerhost}:#{peerport}"
        end

        def use_connection(args)
          @connection_use_mutex.synchronize do
            return super(args)
          ensure
            register_interaction
          end
        end

        # https://github.com/ruby-ldap/ruby-net-ldap/issues/11
        # We want to keep the ldap connection open to use later
        # but there's no built in way within the `Net::LDAP` library to do that
        # so we're adding this function to do it instead
        # @param connect_opts [Hash] Options for the LDAP connection.
        def self._open(connect_opts)
          client = new(connect_opts)
          client._open
        end

        # https://github.com/ruby-ldap/ruby-net-ldap/issues/11
        def _open
          raise Net::LDAP::AlreadyOpenedError, 'Open already in progress' if @open_connection

          instrument 'open.net_ldap' do |payload|
            @open_connection = new_connection
            @socket = @open_connection.socket
            payload[:connection] = @open_connection
            payload[:bind] = @result = @open_connection.bind(@auth)
            register_interaction
            return self
          end
        end

        def discover_schema_naming_context
          result = search(base: '', attributes: [:schemanamingcontext], scope: Net::LDAP::SearchScope_BaseObject)
          if result.first && !result.first[:schemanamingcontext].empty?
            schema_dn = result.first[:schemanamingcontext].first
            ilog("#{peerinfo} Discovered Schema DN: #{schema_dn}")
            return schema_dn
          end
          wlog("#{peerinfo} Could not discover Schema DN")
          nil
        end

        def discover_base_dn
          unless naming_contexts
            elog("#{peerinfo} Base DN cannot be determined, no naming contexts available")
            return
          end

          # NOTE: Find the first entry that starts with `DC=` as this will likely be the base DN.
          result = naming_contexts.select { |context| context =~ /^([Dd][Cc]=[A-Za-z0-9-]+,?)+$/ }
                                  .reject { |context| context =~ /(Configuration)|(Schema)|(ForestDnsZones)/ }
          if result.blank?
            elog("#{peerinfo} A base DN matching the expected format could not be found!")
            return
          end
          base_dn = result[0]

          dlog("#{peerinfo} Discovered base DN: #{base_dn}")
          base_dn
        end

        # Monkeypatch upstream library to support the extended Whoami request. Delete
        # this after https://github.com/ruby-ldap/ruby-net-ldap/pull/425 is released.
        # This is not the only occurrence of a patch for this functionality.
        def ldapwhoami(args = {})
          instrument "ldapwhoami.net_ldap", args do |payload|
            @result = use_connection(args, &:ldapwhoami)
            if @result.success?
              @result.extended_response
            else
              raise Net::LDAP::Error, "#{peerinfo} LDAP Error: #{@result.error_message}"
            end
          end
        end
      end
    end
  end
end
