require 'forwardable'
require 'net/ldap'
require 'rex/socket'

#
# This file monkeypatches the upstream net/ldap library to add support for the proxies datastore option,
# supporting blocking synchronrous reads, and using a Rex Socket to work with Rex's Switchboard functionality
# TODO: write a real LDAP client in Rex and migrate all consumers
#

# Update Net::LDAP's initialize and new_connection method to honor a tracking proxies setting
class Net::LDAP
  # Reference the old initialize method, and ensure `reload_lib -a` doesn't attempt to refine the method
  alias_method :_old_initialize, :initialize unless defined?(_old_initialize)

  # Original Source:
  # https://github.com/ruby-ldap/ruby-net-ldap/blob/95cec3822cd2f60787971e19714f74fd5999595c/lib/net/ldap.rb#L548
  # Additionally tracks proxies configuration, used when making a new_connection
  def initialize(args = {})
    _old_initialize(args)
    @proxies = args[:proxies]
  end

  private

  # Original source:
  # https://github.com/ruby-ldap/ruby-net-ldap/blob/95cec3822cd2f60787971e19714f74fd5999595c/lib/net/ldap.rb#L1321
  # Updated to include proxies configuration
  def new_connection
    connection = Net::LDAP::Connection.new \
    :host                    => @host,
    :port                    => @port,
    :hosts                   => @hosts,
    :encryption              => @encryption,
    :instrumentation_service => @instrumentation_service,
    :connect_timeout         => @connect_timeout,
    # New:
    :proxies                 => @proxies

    # Force connect to see if there's a connection error
    connection.socket
    connection
  rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT => e
    @result = {
      :resultCode   => 52,
      :errorMessage => ResultStrings[ResultCodeUnavailable],
    }
    raise e
  end
end

# Update Net::LDAP's initialize and new_connection method to honor a tracking proxies setting
class Net::LDAP::Connection # :nodoc:
  module SynchronousRead
    # Read `length` bytes of data from the LDAP connection socket and
    # return this data as a string.
    #
    # @param length [Integer] Length of the data to be read from the LDAP connection socket.
    # @param _opts [Hash] Unused
    #
    # @return [String] A string containing the data read from the LDAP connection socket.
    def read(length = nil, _opts = {})
      data = ''
      loop do
        chunk = super(length - data.length)
        if chunk.nil?
          return data == '' ? nil : data
        end

        data << chunk
        break if data.length == length
      end

      data
    end
  end

  # Allow wrapping the socket to read and write SASL data
  module SocketSaslIO
    include Rex::Proto::Sasl

    # This seems hacky, but we're just fitting in with how net-ldap does it
    def get_ber_length(data)
      n = data[0].ord

      if n <= 0x7f
        [n, 1]
      elsif n == 0x80
        raise Net::BER::BerError,
            'Indeterminite BER content length not implemented.'
      elsif n == 0xff
        raise Net::BER::BerError, 'Invalid BER length 0xFF detected.'
      else
        v = 0
        extra_length = n & 0x7f
        data[1,n & 0x7f].each_byte do |b|
          v = (v << 8) + b
        end

        [v, extra_length + 1]
      end
    end

    def read_ber(syntax = nil)
      unless @wrap_read.nil?
        if ber_cache.any?
          return ber_cache.shift
        end
        # SASL buffer length
        length_bytes = read(4)
        # The implementation in net-ldap returns nil if it doesn't read any data
        return nil unless length_bytes

        length = length_bytes.unpack('N')[0]

        # Now read the actual data
        data = read(length)

        # Decrypt it
        plaintext = @wrap_read.call(data)

        while plaintext.length > 0
          id = plaintext[0].ord
          ber_length, used_chars = get_ber_length(plaintext[1,plaintext.length])
          plaintext = plaintext[1+used_chars, plaintext.length]

          # We may receive several objects in the one packet
          # Ideally we'd refactor all of ruby-net-ldap to use
          # yields for this, but it's all a bit messy. So instead,
          # just store them all and return the next one each time
          # we're asked.
          ber_cache.append(parse_ber_object(syntax, id, plaintext[0,ber_length]))

          plaintext = plaintext[ber_length,plaintext.length]
        end

        return ber_cache.shift
      else
        super(syntax)
      end
    end

    def write(data)
      unless @wrap_write.nil?
        # Encrypt it
        data = @wrap_write.call(data)

        # Prepend the length bytes
        data = wrap_sasl(data)
      end

      super(data)
    end

    def setup(wrap_read, wrap_write)
      @wrap_read = wrap_read
      @wrap_write = wrap_write
      @ber_cache = []
    end

    private

    attr_accessor :wrap_read
    attr_accessor :wrap_write
    attr_accessor :ber_cache
  end

  module ConnectionSaslIO
    # Provide the encryption wrapper for the caller to set up
    def wrap_read_write(wrap_read, wrap_write)
      @conn.extend(SocketSaslIO)
      @conn.setup(wrap_read, wrap_write)
    end
  end

  # Initialize the LDAP connection using Rex::Socket::TCP,
  # and optionally set up encryption on the connection if configured.
  #
  # @param server [Hash] Hash of the options needed to set
  #   up the Rex::Socket::TCP socket for the LDAP connection.
  # @see http://gemdocs.org/gems/rex-socket/0.1.43/Rex/Socket.html#create-class_method
  # @see http://gemdocs.org/gems/rex-socket/0.1.43/Rex/Socket.html#create_param-class_method
  # @see http://gemdocs.org/gems/rex-socket/0.1.43/Rex/Socket/Parameters.html#from_hash-class_method
  def initialize(server)
    begin
      @conn = Rex::Socket::Tcp.create(
        'PeerHost' => server[:host],
        'PeerPort' => server[:port],
        'Proxies' => server[:proxies],
        'Timeout' => server[:connect_timeout]
      )
      @conn.extend(SynchronousRead)

      # Set up read/write wrapping
      self.extend(ConnectionSaslIO)
    rescue SocketError
      raise Net::LDAP::LdapError, 'No such address or other socket error.'
    rescue Errno::ECONNREFUSED
      raise Net::LDAP::LdapError, "Server #{server[:host]} refused connection on port #{server[:port]}."
    end

    if server[:encryption]
      setup_encryption server[:encryption]
      @conn.extend Forwardable
      @conn.def_delegators :@io, :localinfo, :peerinfo
    end

    yield self if block_given?
  end
end

module Rex
  module Proto
    module LDAP
    end
  end
end
