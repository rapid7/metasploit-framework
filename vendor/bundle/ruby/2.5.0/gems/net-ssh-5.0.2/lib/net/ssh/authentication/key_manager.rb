require 'net/ssh/errors'
require 'net/ssh/key_factory'
require 'net/ssh/loggable'
require 'net/ssh/authentication/agent'

module Net
  module SSH
    module Authentication

      # A trivial exception class used to report errors in the key manager.
      class KeyManagerError < Net::SSH::Exception; end

      # This class encapsulates all operations done by clients on a user's
      # private keys. In practice, the client should never need a reference
      # to a private key; instead, they grab a list of "identities" (public
      # keys) that are available from the KeyManager, and then use
      # the KeyManager to do various private key operations using those
      # identities.
      #
      # The KeyManager also uses the Agent class to encapsulate the
      # ssh-agent. Thus, from a client's perspective it is completely
      # hidden whether an identity comes from the ssh-agent or from a file
      # on disk.
      class KeyManager
        include Loggable

        # The list of user key files that will be examined
        attr_reader :key_files

        # The list of user key data that will be examined
        attr_reader :key_data

        # The map of loaded identities
        attr_reader :known_identities

        # The map of options that were passed to the key-manager
        attr_reader :options

        # Create a new KeyManager. By default, the manager will
        # use the ssh-agent if it is running and the `:use_agent` option
        # is not false.
        def initialize(logger, options={})
          self.logger = logger
          @key_files = []
          @key_data = []
          @use_agent = options[:use_agent] != false
          @known_identities = {}
          @agent = nil
          @options = options
        end

        # Clear all knowledge of any loaded user keys. This also clears the list
        # of default identity files that are to be loaded, thus making it
        # appropriate to use if a client wishes to NOT use the default identity
        # files.
        def clear!
          key_files.clear
          key_data.clear
          known_identities.clear
          self
        end

        # Add the given key_file to the list of key files that will be used.
        def add(key_file)
          key_files.push(File.expand_path(key_file)).uniq!
          self
        end

        # Add the given key_file to the list of keys that will be used.
        def add_key_data(key_data_)
          key_data.push(key_data_).uniq!
          self
        end

        # This is used as a hint to the KeyManager indicating that the agent
        # connection is no longer needed. Any other open resources may be closed
        # at this time.
        #
        # Calling this does NOT indicate that the KeyManager will no longer
        # be used. Identities may still be requested and operations done on
        # loaded identities, in which case, the agent will be automatically
        # reconnected. This method simply allows the client connection to be
        # closed when it will not be used in the immediate future.
        def finish
          @agent.close if @agent
          @agent = nil
        end

        # Iterates over all available identities (public keys) known to this
        # manager. As it finds one, it will then yield it to the caller.
        # The origin of the identities may be from files on disk or from an
        # ssh-agent. Note that identities from an ssh-agent are always listed
        # first in the array, with other identities coming after.
        #
        # If key manager was created with :keys_only option, any identity
        # from ssh-agent will be ignored unless it present in key_files or
        # key_data.
        def each_identity
          prepared_identities = prepare_identities_from_files + prepare_identities_from_data

          user_identities = load_identities(prepared_identities, false, true)

          if agent
            agent.identities.each do |key|
              corresponding_user_identity = user_identities.detect { |identity|
                identity[:public_key] && identity[:public_key].to_pem == key.to_pem
              }
              user_identities.delete(corresponding_user_identity) if corresponding_user_identity

              if !options[:keys_only] || corresponding_user_identity
                known_identities[key] = { from: :agent }
                yield key
              end
            end
          end

          user_identities = load_identities(user_identities, !options[:non_interactive], false)

          user_identities.each do |identity|
            key = identity.delete(:public_key)
            known_identities[key] = identity
            yield key
          end

          self
        end

        # Sign the given data, using the corresponding private key of the given
        # identity. If the identity was originally obtained from an ssh-agent,
        # then the ssh-agent will be used to sign the data, otherwise the
        # private key for the identity will be loaded from disk (if it hasn't
        # been loaded already) and will then be used to sign the data.
        #
        # Regardless of the identity's origin or who does the signing, this
        # will always return the signature in an SSH2-specified "signature
        # blob" format.
        def sign(identity, data)
          info = known_identities[identity] or raise KeyManagerError, "the given identity is unknown to the key manager"

          if info[:key].nil? && info[:from] == :file
            begin
              info[:key] = KeyFactory.load_private_key(info[:file], options[:passphrase], !options[:non_interactive])
            rescue OpenSSL::OpenSSLError, Exception => e
              raise KeyManagerError, "the given identity is known, but the private key could not be loaded: #{e.class} (#{e.message})"
            end
          end

          if info[:key]
            return Net::SSH::Buffer.from(:string, identity.ssh_signature_type,
              :mstring, info[:key].ssh_do_sign(data.to_s)).to_s
          end

          if info[:from] == :agent
            raise KeyManagerError, "the agent is no longer available" unless agent
            return agent.sign(identity, data.to_s)
          end

          raise KeyManagerError, "[BUG] can't determine identity origin (#{info.inspect})"
        end

        # Identifies whether the ssh-agent will be used or not.
        def use_agent?
          @use_agent
        end

        # Toggles whether the ssh-agent will be used or not. If true, an
        # attempt will be made to use the ssh-agent. If false, any existing
        # connection to an agent is closed and the agent will not be used.
        def use_agent=(use_agent)
          finish if !use_agent
          @use_agent = use_agent
        end

        # Returns an Agent instance to use for communicating with an SSH
        # agent process. Returns nil if use of an SSH agent has been disabled,
        # or if the agent is otherwise not available.
        def agent
          return unless use_agent?
          @agent ||= Agent.connect(logger, options[:agent_socket_factory])
        rescue AgentNotAvailable
          @use_agent = false
          nil
        end

        def no_keys?
          key_files.empty? && key_data.empty?
        end

        private

        # Prepares identities from user key_files for loading, preserving their order and sources.
        def prepare_identities_from_files
          key_files.map do |file|
            if readable_file?(file)
              identity = {}
              cert_file = file + "-cert.pub"
              public_key_file = file + ".pub"
              if readable_file?(cert_file)
                identity[:load_from] = :pubkey_file
                identity[:pubkey_file] = cert_file
              elsif readable_file?(public_key_file)
                identity[:load_from] = :pubkey_file
                identity[:pubkey_file] = public_key_file
              else
                identity[:load_from] = :privkey_file
              end
              identity.merge(privkey_file: file)
            end
          end.compact
        end

        def readable_file?(path)
          File.file?(path) && File.readable?(path)
        end

        # Prepared identities from user key_data, preserving their order and sources.
        def prepare_identities_from_data
          key_data.map do |data|
            { load_from: :data, data: data }
          end
        end

        # Load prepared identities. Private key decryption errors ignored if ignore_decryption_errors
        def load_identities(identities, ask_passphrase, ignore_decryption_errors)
          identities.map do |identity|
            begin
              case identity[:load_from]
              when :pubkey_file
                key = KeyFactory.load_public_key(identity[:pubkey_file])
                { public_key: key, from: :file, file: identity[:privkey_file] }
              when :privkey_file
                private_key = KeyFactory.load_private_key(identity[:privkey_file], options[:passphrase], ask_passphrase, options[:password_prompt])
                key = private_key.send(:public_key)
                { public_key: key, from: :file, file: identity[:privkey_file], key: private_key }
              when :data
                private_key = KeyFactory.load_data_private_key(identity[:data], options[:passphrase], ask_passphrase, "<key in memory>", options[:password_prompt])
                key = private_key.send(:public_key)
                { public_key: key, from: :key_data, data: identity[:data], key: private_key }
              else
                identity
              end
            rescue OpenSSL::PKey::RSAError, OpenSSL::PKey::DSAError, OpenSSL::PKey::ECError, OpenSSL::PKey::PKeyError, ArgumentError => e
              if ignore_decryption_errors
                identity
              else
                process_identity_loading_error(identity, e)
                nil
              end
            rescue Exception => e
              process_identity_loading_error(identity, e)
              nil
            end
          end.compact
        end

        def process_identity_loading_error(identity, e)
          case identity[:load_from]
          when :pubkey_file
            error { "could not load public key file `#{identity[:pubkey_file]}': #{e.class} (#{e.message})" }
          when :privkey_file
            error { "could not load private key file `#{identity[:privkey_file]}': #{e.class} (#{e.message})" }
          else
            raise e
          end
        end
      end
    end
  end
end
