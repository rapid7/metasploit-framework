module Net; module SSH
  # A general exception class, to act as the ancestor of all other Net::SSH
  # exception classes.
  class Exception < ::RuntimeError; end

  # This exception is raised when authentication fails (whether it be
  # public key authentication, password authentication, or whatever).
  class AuthenticationFailed < Exception; end

  # This exception is raised when the remote host has disconnected
  # unexpectedly.
  class Disconnect < Exception; end

  # This exception is primarily used internally, but if you have a channel
  # request handler (see Net::SSH::Connection::Channel#on_request) that you
  # want to fail in such a way that the server knows it failed, you can
  # raise this exception in the handler and Net::SSH will translate that into
  # a "channel failure" message.
  class ChannelRequestFailed < Exception; end

  # This is exception is primarily used internally, but if you have a channel
  # open handler (see Net::SSH::Connection::Session#on_open_channel) and you
  # want to fail in such a way that the server knows it failed, you can
  # raise this exception in the handler and Net::SSH will translate that into
  # a "channel open failed" message.
  class ChannelOpenFailed < Exception
    attr_reader :code, :reason

    def initialize(code, reason)
      @code, @reason = code, reason
      super "#{reason} (#{code})"
    end
  end

  # Raised when the cached key for a particular host does not match the
  # key given by the host, which can be indicative of a man-in-the-middle
  # attack. When rescuing this exception, you can inspect the key fingerprint
  # and, if you want to proceed anyway, simply call the remember_host!
  # method on the exception, and then retry.
  class HostKeyMismatch < Exception
    # the callback to use when #remember_host! is called
    attr_writer :callback #:nodoc:

    # situation-specific data describing the host (see #host, #port, etc.)
    attr_writer :data #:nodoc:

    # An accessor for getting at the data that was used to look up the host
    # (see also #fingerprint, #host, #port, #ip, and #key).
    def [](key)
      @data && @data[key]
    end

    # Returns the fingerprint of the key for the host, which either was not
    # found or did not match.
    def fingerprint
      @data && @data[:fingerprint]
    end

    # Returns the host name for the remote host, as reported by the socket.
    def host
      @data && @data[:peer] && @data[:peer][:host]
    end

    # Returns the port number for the remote host, as reported by the socket.
    def port
      @data && @data[:peer] && @data[:peer][:port]
    end

    # Returns the IP address of the remote host, as reported by the socket.
    def ip
      @data && @data[:peer] && @data[:peer][:ip]
    end

    # Returns the key itself, as reported by the remote host.
    def key
      @data && @data[:key]
    end

    # Tell Net::SSH to record this host and key in the known hosts file, so
    # that subsequent connections will remember them.
    def remember_host!
      @callback.call
    end
  end
end; end