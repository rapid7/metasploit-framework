# -*- coding: binary -*-
require 'rex/proto/ssh/hrr_rb_ssh'

module Rex
module Proto
module Ssh

##
# Whitelist-based access control scaffold
##
module AccessControlList

  #
  # Add permitted access control entry to access control list
  # Create ACL if it does not yet exist
  #
  # @param host [String] Host/hostname for which to grant access
  # @param port [Integer] Port for which to grant access
  # @param bind [TrueClass,FalseClass] Whether this ACE is for servers
  #
  def permit=(host, port, bind = false)
    @acl ||= { bind:[], connect:[] }
    unless permit?(host, port, bind)
      @acl[ bind ? :bind : :connect ] << "#{host}:#{port}"
    end
  end

  #
  # Delete permitted access control entry from access control list
  #
  # @param host [String] Host/hostname for which to grant access
  # @param port [Integer] Port for which to grant access
  # @param bind [TrueClass,FalseClass] Whether this ACE is for servers
  #
  def deny=(host, port, bind = false)
    @acl[ bind ? :bind : :connect ].select! do |ent|
      ent != "#{host}:#{port}"
    end if @acl
  end

  #
  # Check if access control entry exists in access control list
  #
  # @param host [String] Host/hostname for which to check access
  # @param port [Integer] Port for which to check access
  # @param bind [TrueClass,FalseClass] Whether this ACE is for servers
  #
  # @return [TrueClass,FalseClass] Permission boolean for access
  def permit?(host, port, bind = false)
    @acl and ["#{host}:#{port}", "*:*", "#{host}:*", "*:#{port}"].any? do |m|
      @acl[ bind ? :bind : :connect ].include?(m)
    end
  end
end

##
# Encapsulation of Connection constructor for Rex use
# Provides ACLs for port forwarding and client (io) access hooks
##
class Connection < ::HrrRbSsh::Connection
  include AccessControlList
  def self.default_options
    noneauth = HrrRbSsh::Authentication::Authenticator.new { |context| true }
    return {
      'authentication_none_authenticator' => noneauth,
      'authentication_password_authenticator' => noneauth,
      'authentication_publickey_authenticator' => noneauth,
      'authentication_keyboard_interactive_authenticator' => noneauth,
      'local_version' => 'SSH-2.0-RexProtoSsh'
    }
  end
  #
  # Create new Connection from an IO and options set, pull trans
  # and auth from options if present, create from options set otherwise.
  #
  # Creates a default empty handler set for channel requests.
  #
  # @param io [IO] Socket, FD, or abstraction on which to build Connection
  # @param options [Hash] Options for constructing Connection components
  #
  # @return [Rex::Proto::Ssh::Connection] a new connection object
  def initialize(io = nil, options = self.default_options, context = {})
    def_handler = HrrRbSsh::Connection::RequestHandler.new {|c| }
    @cfd_handlers = {
      'connection_channel_request_pty_req'       => def_handler,
      'connection_channel_request_env'           => def_handler,
      'connection_channel_request_shell'         => def_handler,
      'connection_channel_request_exec'          => def_handler,
      'connection_channel_request_window_change' => def_handler
    }
    @context = context
    @logger = Logger.new self.class.name
    @server = options.delete(:ssh_server)
    # Take a pre-built transport from the options or build one on the fly
    @transport = options.delete(:ssh_transport) || HrrRbSsh::Transport.new(
      io,
      options.delete(:ssh_mode) || :server,
      options.merge(@cfd_handlers)
    )
    # Take a pre-built authentication from the options or build one on the fly
    @authentication = options.delete(:ssh_authentication) ||
      HrrRbSsh::Authentication.new(@transport, options.merge(@cfd_handlers))
    @global_request_handler = GlobalRequestHandler.new(self)
    # Retain remaining options for later use
    @options = options

    @channels = Hash.new
    @username = nil
    @closed = nil
  end

  #
  # Provide keys of explicitly not closed channels
  #
  # @param ctype [String] Channel type to select, nil for all
  #
  # @return [Array] Array of integers indexing open channels
  def open_channel_keys(ctype = 'session')
    channels.keys.sort.select do |cn|
      channels[cn].closed? === false and (
        ctype.nil? or channels[cn].channel_type == ctype
      )
    end
  end

  #
  # Provide IO from which to read remote-end inputs
  #
  # @param fd [Integer] Desired descriptor from which to read
  # @param cn [Integer] Desired channel from which to take fd
  #
  # @return [IO] File descriptor for reading
  def reader(fd = 0, cn = open_channel_keys.first)
    channels[cn].io[fd]
  end

  #
  # Provide IO into which writes to the remote end can be sent
  #
  # @param fd [Integer] Desired descriptor to which to write
  # @param cn [Integer] Desired channel from which to take fd
  #
  # @return [IO] File descriptor for writing
  def writer(fd = 1, cn = open_channel_keys.first)
    channels[cn].io[fd]
  end

  #
  # Close the connection and underlying socket
  #
  def close
    super
    @transport.io.close if @transport and !@transport.io.closed?
  end

  attr_accessor :transport, :authentication, :channels, :global_request_handler
  attr_reader :server, :context
end

##
# Create a monitored relay between channel IOs and external FD-like objects
##
class ChannelRelay
  include Rex::IO::SocketAbstraction

  def initialize(src, dst, threadname = "SshChannelMonitorRemote")
    initialize_abstraction(src, dst)
  end

  def initialize_abstraction(src, dst, threadname)
    self.rsock = src
    self.lsock = dst
    monitor_rsock(threadname)
  end
end

##
# A modified Rex::IO::Stream for separate file descriptors
# consumers are responsible for relevant initialization and
# fd_rd+fd_wr methods to expose selectable R/W IOs.
##
module IOMergeAbstraction
  def inspect
    "#{self.class}(#{fd_rd.inspect}|#{fd_wr.inspect})"
  end

  def write(buf, opts = {})
    total_sent   = 0
    total_length = buf.length
    block_size   = 32768

    begin
      while( total_sent < total_length )
        s = Rex::ThreadSafe.select( nil, [ fd_wr ], nil, 0.2 )
        if( s == nil || s[0] == nil )
          next
        end
        data = buf[total_sent, block_size]
        sent = fd_wr.write_nonblock( data )
        if sent > 0
          total_sent += sent
        end
      end
    rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
      # Sleep for a half a second, or until we can write again
      Rex::ThreadSafe.select( nil, [ fd_wr ], nil, 0.5 )
      # Decrement the block size to handle full sendQs better
      block_size = 1024
      # Try to write the data again
      retry
    rescue ::IOError, ::Errno::EPIPE
      return nil
    end

    total_sent
  end

  #
  # This method reads data of the supplied length from the stream.
  #
  def read(length = nil, opts = {})

    begin
      return fd_rd.read_nonblock( length )
    rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
      # Sleep for a half a second, or until we can read again
      Rex::ThreadSafe.select( [ fd_rd ], nil, nil, 0.5 )
      # Decrement the block size to handle full sendQs better
      retry
    rescue ::IOError, ::Errno::EPIPE
      return nil
    end
  end

  #
  # Polls the stream to see if there is any read data available.  Returns
  # true if data is available for reading, otherwise false is returned.
  #
  def has_read_data?(timeout = nil)

    # Allow a timeout of "0" that waits almost indefinitely for input, this
    # mimics the behavior of Rex::ThreadSafe.select() and fixes some corner
    # cases of unintentional no-wait timeouts.
    timeout = 3600 if (timeout and timeout == 0)

    begin
      if ((rv = ::IO.select([ fd_rd ], nil, nil, timeout)) and
          (rv[0]) and
          (rv[0][0] == fd_rd))
        true
      else
        false
      end
    rescue ::Errno::EBADF, ::Errno::ENOTSOCK
      raise ::EOFError
    rescue StreamClosedError, ::IOError, ::EOFError, ::Errno::EPIPE
      #  Return false if the socket is dead
      return false
    end
  end

  def close
    fd_rd.close unless fd_rd.closed?
    fd_wr.close unless fd_wr.closed?
  end

  def closed?
    fd_rd.closed? and fd_wr.closed?
  end
end

##
# Emulate a single bidirectional IO using the clients Connections Channels IOs
##
class ChannelFD
  include Rex::IO::Stream
  include IOMergeAbstraction
  def initialize(parent, chan_id = nil)
    @parent = parent
  end

  def inspect
    "#{super}/#{@parent.inspect}"
  end

  def close
    super
    @parent.close unless @parent.closed?
  end

  def closed?
    super and @parent.closed?
  end

  def cid
    @cid ||= @parent.connection.open_channel_keys.first
    @cid
  end

  def cid=(chan_id)
    if @parent.connection.open_channel_keys.include?(chan_id)
      @cid = chan_id
    else
      raise "Invalid Channel ID passed to #{self.inspect}"
    end
  end
  attr_reader :parent, :cid

private

  #
  # Provide a selectable filedescriptor open for reading
  #
  # @return [IO] Descriptor for reading
  def fd_rd
    begin
      channel.io[0]
    rescue
    end
  end

  #
  # Provide a selectable filedescriptor open for writing
  #
  # @param fd [Symbol] Output FD type, anything but :stderr uses 1 (STDOUT)
  #
  # @return [IO] Descriptor for writing
  def fd_wr(fd = :stdout)
    begin
      channel.io[(fd == :stderr ? 2 : 1)]
    rescue
    end
  end

  #
  # Expose a Channel from the Connection
  #
  # @return [HrrRbSsh::Connection::Channel] Channel object
  def channel
    @parent.connection.channels[cid]
  end
end

end
end
end