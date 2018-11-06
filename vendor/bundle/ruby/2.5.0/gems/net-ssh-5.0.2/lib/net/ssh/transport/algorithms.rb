require 'net/ssh/buffer'
require 'net/ssh/known_hosts'
require 'net/ssh/loggable'
require 'net/ssh/transport/cipher_factory'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/hmac'
require 'net/ssh/transport/kex'
require 'net/ssh/transport/server_version'
require 'net/ssh/authentication/ed25519_loader'

module Net 
  module SSH 
    module Transport

      # Implements the higher-level logic behind an SSH key-exchange. It handles
      # both the initial exchange, as well as subsequent re-exchanges (as needed).
      # It also encapsulates the negotiation of the algorithms, and provides a
      # single point of access to the negotiated algorithms.
      #
      # You will never instantiate or reference this directly. It is used
      # internally by the transport layer.
      class Algorithms
        include Loggable
        include Constants
    
        # Define the default algorithms, in order of preference, supported by
        # Net::SSH.
        ALGORITHMS = {
          host_key: %w[ssh-rsa ssh-dss
                       ssh-rsa-cert-v01@openssh.com
                       ssh-rsa-cert-v00@openssh.com],
          kex: %w[diffie-hellman-group-exchange-sha1
                  diffie-hellman-group1-sha1
                  diffie-hellman-group14-sha1
                  diffie-hellman-group-exchange-sha256],
          encryption: %w[aes128-cbc 3des-cbc blowfish-cbc cast128-cbc
                         aes192-cbc aes256-cbc rijndael-cbc@lysator.liu.se
                         idea-cbc arcfour128 arcfour256 arcfour
                         aes128-ctr aes192-ctr aes256-ctr
                         cast128-ctr blowfish-ctr 3des-ctr none],
    
          hmac: %w[hmac-sha1 hmac-md5 hmac-sha1-96 hmac-md5-96
                   hmac-ripemd160 hmac-ripemd160@openssh.com
                   hmac-sha2-256 hmac-sha2-512 hmac-sha2-256-96
                   hmac-sha2-512-96 none],
    
          compression: %w[none zlib@openssh.com zlib],
          language: %w[]
        }
        if defined?(OpenSSL::PKey::EC)
          ALGORITHMS[:host_key] += %w[ecdsa-sha2-nistp256
                                      ecdsa-sha2-nistp384
                                      ecdsa-sha2-nistp521]
          ALGORITHMS[:host_key] += %w[ssh-ed25519] if Net::SSH::Authentication::ED25519Loader::LOADED
          ALGORITHMS[:kex] += %w[ecdh-sha2-nistp256
                                 ecdh-sha2-nistp384
                                 ecdh-sha2-nistp521]
        end
    
        # The underlying transport layer session that supports this object
        attr_reader :session
    
        # The hash of options used to initialize this object
        attr_reader :options
    
        # The kex algorithm to use settled on between the client and server.
        attr_reader :kex
    
        # The type of host key that will be used for this session.
        attr_reader :host_key
    
        # The type of the cipher to use to encrypt packets sent from the client to
        # the server.
        attr_reader :encryption_client
    
        # The type of the cipher to use to decrypt packets arriving from the server.
        attr_reader :encryption_server
    
        # The type of HMAC to use to sign packets sent by the client.
        attr_reader :hmac_client
    
        # The type of HMAC to use to validate packets arriving from the server.
        attr_reader :hmac_server
    
        # The type of compression to use to compress packets being sent by the client.
        attr_reader :compression_client
    
        # The type of compression to use to decompress packets arriving from the server.
        attr_reader :compression_server
    
        # The language that will be used in messages sent by the client.
        attr_reader :language_client
    
        # The language that will be used in messages sent from the server.
        attr_reader :language_server
    
        # The hash of algorithms preferred by the client, which will be told to
        # the server during algorithm negotiation.
        attr_reader :algorithms
    
        # The session-id for this session, as decided during the initial key exchange.
        attr_reader :session_id
    
        # Returns true if the given packet can be processed during a key-exchange.
        def self.allowed_packet?(packet)
          (1..4).include?(packet.type) ||
          (6..19).include?(packet.type) ||
          (21..49).include?(packet.type)
        end
    
        # Instantiates a new Algorithms object, and prepares the hash of preferred
        # algorithms based on the options parameter and the ALGORITHMS constant.
        def initialize(session, options={})
          @session = session
          @logger = session.logger
          @options = options
          @algorithms = {}
          @pending = @initialized = false
          @client_packet = @server_packet = nil
          prepare_preferred_algorithms!
        end
    
        # Start the algorithm negotation
        def start
          raise ArgumentError, "Cannot call start if it's negotiation started or done" if @pending || @initialized
          send_kexinit
        end
    
        # Request a rekey operation. This will return immediately, and does not
        # actually perform the rekey operation. It does cause the session to change
        # state, however--until the key exchange finishes, no new packets will be
        # processed.
        def rekey!
          @client_packet = @server_packet = nil
          @initialized = false
          send_kexinit
        end
    
        # Called by the transport layer when a KEXINIT packet is received, indicating
        # that the server wants to exchange keys. This can be spontaneous, or it
        # can be in response to a client-initiated rekey request (see #rekey!). Either
        # way, this will block until the key exchange completes.
        def accept_kexinit(packet)
          info { "got KEXINIT from server" }
          @server_data = parse_server_algorithm_packet(packet)
          @server_packet = @server_data[:raw]
          if !pending?
            send_kexinit
          else
            proceed!
          end
        end
    
        # A convenience method for accessing the list of preferred types for a
        # specific algorithm (see #algorithms).
        def [](key)
          algorithms[key]
        end
    
        # Returns +true+ if a key-exchange is pending. This will be true from the
        # moment either the client or server requests the key exchange, until the
        # exchange completes. While an exchange is pending, only a limited number
        # of packets are allowed, so event processing essentially stops during this
        # period.
        def pending?
          @pending
        end

        # Returns true if no exchange is pending, and otherwise returns true or
        # false depending on whether the given packet is of a type that is allowed
        # during a key exchange.
        def allow?(packet)
          !pending? || Algorithms.allowed_packet?(packet)
        end

        # Returns true if the algorithms have been negotiated at all.
        def initialized?
          @initialized
        end

        def host_key_format
          case host_key
          when "ssh-rsa-cert-v01@openssh.com", "ssh-rsa-cert-v00@openssh.com"
            "ssh-rsa"
          else
            host_key
          end
        end

        private

        # Sends a KEXINIT packet to the server. If a server KEXINIT has already
        # been received, this will then invoke #proceed! to proceed with the key
        # exchange, otherwise it returns immediately (but sets the object to the
        # pending state).
        def send_kexinit
          info { "sending KEXINIT" }
          @pending = true
          packet = build_client_algorithm_packet
          @client_packet = packet.to_s
          session.send_message(packet)
          proceed! if @server_packet
        end
    
        # After both client and server have sent their KEXINIT packets, this
        # will do the algorithm negotiation and key exchange. Once both finish,
        # the object leaves the pending state and the method returns.
        def proceed!
          info { "negotiating algorithms" }
          negotiate_algorithms
          exchange_keys
          @pending = false
        end
    
        # Prepares the list of preferred algorithms, based on the options hash
        # that was given when the object was constructed, and the ALGORITHMS
        # constant. Also, when determining the host_key type to use, the known
        # hosts files are examined to see if the host has ever sent a host_key
        # before, and if so, that key type is used as the preferred type for
        # communicating with this server.
        def prepare_preferred_algorithms!
          options[:compression] = %w[zlib@openssh.com zlib] if options[:compression] == true
    
          ALGORITHMS.each do |algorithm, supported|
            algorithms[algorithm] = compose_algorithm_list(supported, options[algorithm], options[:append_all_supported_algorithms])
          end
    
          # for convention, make sure our list has the same keys as the server
          # list
    
          algorithms[:encryption_client ] = algorithms[:encryption_server ] = algorithms[:encryption]
          algorithms[:hmac_client       ] = algorithms[:hmac_server       ] = algorithms[:hmac]
          algorithms[:compression_client] = algorithms[:compression_server] = algorithms[:compression]
          algorithms[:language_client   ] = algorithms[:language_server   ] = algorithms[:language]
    
          if !options.key?(:host_key)
            # make sure the host keys are specified in preference order, where any
            # existing known key for the host has preference.
    
            existing_keys = session.host_keys
            host_keys = existing_keys.map { |key| key.ssh_type }.uniq
            algorithms[:host_key].each do |name|
              host_keys << name unless host_keys.include?(name)
            end
            algorithms[:host_key] = host_keys
          end
        end
    
        # Composes the list of algorithms by taking supported algorithms and matching with supplied options.
        def compose_algorithm_list(supported, option, append_all_supported_algorithms = false)
          return supported.dup unless option
    
          list = []
          option = Array(option).compact.uniq
    
          if option.first && option.first.start_with?('+')
            list = supported.dup
            list << option.first[1..-1]
            list.concat(option[1..-1])
            list.uniq!
          else
            list = option
    
            if append_all_supported_algorithms
              supported.each { |name| list << name unless list.include?(name) }
            end
          end
    
          unsupported = []
          list.select! do |name|
            is_supported = supported.include?(name)
            unsupported << name unless is_supported
            is_supported
          end
    
          lwarn { %(unsupported algorithm: `#{unsupported}') } unless unsupported.empty?
    
          list
        end
    
        # Parses a KEXINIT packet from the server.
        def parse_server_algorithm_packet(packet)
          data = { raw: packet.content }
    
          packet.read(16) # skip the cookie value
    
          data[:kex]                = packet.read_string.split(/,/)
          data[:host_key]           = packet.read_string.split(/,/)
          data[:encryption_client]  = packet.read_string.split(/,/)
          data[:encryption_server]  = packet.read_string.split(/,/)
          data[:hmac_client]        = packet.read_string.split(/,/)
          data[:hmac_server]        = packet.read_string.split(/,/)
          data[:compression_client] = packet.read_string.split(/,/)
          data[:compression_server] = packet.read_string.split(/,/)
          data[:language_client]    = packet.read_string.split(/,/)
          data[:language_server]    = packet.read_string.split(/,/)
    
          # TODO: if first_kex_packet_follows, we need to try to skip the
          # actual kexinit stuff and try to guess what the server is doing...
          # need to read more about this scenario.
          # first_kex_packet_follows = packet.read_bool
    
          return data
        end
    
        # Given the #algorithms map of preferred algorithm types, this constructs
        # a KEXINIT packet to send to the server. It does not actually send it,
        # it simply builds the packet and returns it.
        def build_client_algorithm_packet
          kex         = algorithms[:kex].join(",")
          host_key    = algorithms[:host_key].join(",")
          encryption  = algorithms[:encryption].join(",")
          hmac        = algorithms[:hmac].join(",")
          compression = algorithms[:compression].join(",")
          language    = algorithms[:language].join(",")
    
          Net::SSH::Buffer.from(:byte, KEXINIT,
            :long, [rand(0xFFFFFFFF), rand(0xFFFFFFFF), rand(0xFFFFFFFF), rand(0xFFFFFFFF)],
            :mstring, [kex, host_key, encryption, encryption, hmac, hmac],
            :mstring, [compression, compression, language, language],
            :bool, false, :long, 0)
        end
    
        # Given the parsed server KEX packet, and the client's preferred algorithm
        # lists in #algorithms, determine which preferred algorithms each has
        # in common and set those as the selected algorithms. If, for any algorithm,
        # no type can be settled on, an exception is raised.
        def negotiate_algorithms
          @kex                = negotiate(:kex)
          @host_key           = negotiate(:host_key)
          @encryption_client  = negotiate(:encryption_client)
          @encryption_server  = negotiate(:encryption_server)
          @hmac_client        = negotiate(:hmac_client)
          @hmac_server        = negotiate(:hmac_server)
          @compression_client = negotiate(:compression_client)
          @compression_server = negotiate(:compression_server)
          @language_client    = negotiate(:language_client) rescue ""
          @language_server    = negotiate(:language_server) rescue ""
    
          debug do
            "negotiated:\n" +
              %i[kex host_key encryption_server encryption_client hmac_client hmac_server compression_client compression_server language_client language_server].map do |key|
                "* #{key}: #{instance_variable_get("@#{key}")}"
              end.join("\n")
          end
        end
    
        # Negotiates a single algorithm based on the preferences reported by the
        # server and those set by the client. This is called by
        # #negotiate_algorithms.
        def negotiate(algorithm)
          match = self[algorithm].find { |item| @server_data[algorithm].include?(item) }
    
          raise Net::SSH::Exception, "could not settle on #{algorithm} algorithm" if match.nil?
    
          return match
        end
    
        # Considers the sizes of the keys and block-sizes for the selected ciphers,
        # and the lengths of the hmacs, and returns the largest as the byte requirement
        # for the key-exchange algorithm.
        def kex_byte_requirement
          sizes = [8] # require at least 8 bytes
    
          sizes.concat(CipherFactory.get_lengths(encryption_client))
          sizes.concat(CipherFactory.get_lengths(encryption_server))
    
          sizes << HMAC.key_length(hmac_client)
          sizes << HMAC.key_length(hmac_server)
    
          sizes.max
        end
    
        # Instantiates one of the Transport::Kex classes (based on the negotiated
        # kex algorithm), and uses it to exchange keys. Then, the ciphers and
        # HMACs are initialized and fed to the transport layer, to be used in
        # further communication with the server.
        def exchange_keys
          debug { "exchanging keys" }
    
          algorithm = Kex::MAP[kex].new(self, session,
            client_version_string: Net::SSH::Transport::ServerVersion::PROTO_VERSION,
            server_version_string: session.server_version.version,
            server_algorithm_packet: @server_packet,
            client_algorithm_packet: @client_packet,
            need_bytes: kex_byte_requirement,
            minimum_dh_bits: options[:minimum_dh_bits],
            logger: logger)
          result = algorithm.exchange_keys
    
          secret   = result[:shared_secret].to_ssh
          hash     = result[:session_id]
          digester = result[:hashing_algorithm]
    
          @session_id ||= hash
    
          key = Proc.new { |salt| digester.digest(secret + hash + salt + @session_id) }
    
          iv_client = key["A"]
          iv_server = key["B"]
          key_client = key["C"]
          key_server = key["D"]
          mac_key_client = key["E"]
          mac_key_server = key["F"]
    
          parameters = { shared: secret, hash: hash, digester: digester }
    
          cipher_client = CipherFactory.get(encryption_client, parameters.merge(iv: iv_client, key: key_client, encrypt: true))
          cipher_server = CipherFactory.get(encryption_server, parameters.merge(iv: iv_server, key: key_server, decrypt: true))
    
          mac_client = HMAC.get(hmac_client, mac_key_client, parameters)
          mac_server = HMAC.get(hmac_server, mac_key_server, parameters)
    
          session.configure_client cipher: cipher_client, hmac: mac_client,
                                   compression: normalize_compression_name(compression_client),
                                   compression_level: options[:compression_level],
                                   rekey_limit: options[:rekey_limit],
                                   max_packets: options[:rekey_packet_limit],
                                   max_blocks: options[:rekey_blocks_limit]
    
          session.configure_server cipher: cipher_server, hmac: mac_server,
                                   compression: normalize_compression_name(compression_server),
                                   rekey_limit: options[:rekey_limit],
                                   max_packets: options[:rekey_packet_limit],
                                   max_blocks: options[:rekey_blocks_limit]
    
          @initialized = true
        end
    
        # Given the SSH name for some compression algorithm, return a normalized
        # name as a symbol.
        def normalize_compression_name(name)
          case name
          when "none"             then false
          when "zlib"             then :standard
          when "zlib@openssh.com" then :delayed
          else raise ArgumentError, "unknown compression type `#{name}'"
          end
        end
      end
    end
  end
end
