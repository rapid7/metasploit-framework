# -*- coding: binary -*-

require 'msf/core/exploit/remote/winrm'
require 'winrm'

module Msf::Sessions
  #
  # This class provides a session for WinRM client connections, where Metasploit
  # has authenticated to a remote WinRM instance.
  #
  class WinrmCommandShell < Msf::Sessions::CommandShell

    class WinrmSocketWrapper
      include Rex::IO::StreamAbstraction

      attr_accessor :lsock, :rsock

      attr_accessor :shell, :closed, :conn

      module PeerInfo
        include ::Rex::IO::Stream
        attr_accessor :peerinfo
        attr_accessor :localinfo
      end
      
      def initialize(conn, addr, port)
        self.conn = conn
        self.shell = conn.shell(:powershell)

        initialize_abstraction
        self.lsock.extend(PeerInfo)
        self.lsock.peerinfo = "[#{addr}]:#{port}"
        self.lsock.localinfo = "[127.0.0.1]"
      end
     
     def closed?
        self.closed
      end

      def close
        cleanup_abstraction
        self.shell.close
        self.closed = true
      end

      def close_write
        if closed?
          raise IOError, 'Channel has been closed.', caller
        end
        self.close
      end

      #
      # Read *length* bytes from the channel. If the operation times out, the data
      # that was read will be returned or nil if no data was read.
      #
      def read(length = nil)
        print_good "proof 2"
        if closed?
          raise IOError, 'Channel has been closed.', caller
        end

        buf = ''
        length = 65536 if length.nil?

        begin
          buf << lsock.recv(length - buf.length) while buf.length < length
        rescue StandardError
          buf = nil if buf.empty?
        end

        buf
      end

      #
      # Write *buf* to the channel, optionally truncating it to *length* bytes.
      #
      # @param [String] buf The data to write to the channel.
      # @param [Integer] length An optional length to truncate *data* to before
      #   sending it.
      def write(buf, length = nil)
        if closed?
          raise IOError, 'Channel has been closed.', caller
        end

        if !length.nil? && buf.length >= length
          buf = buf[0..length]
        end
        begin
          output = self.shell.run(buf) do |stdout, stderr|
            stdout&.each_line do |line|
              self.rsock.syswrite("#{line.rstrip!}\n")
            end
            self.rsock.syswrite(stderr)
          end
        rescue Exception => err
          print_good(err.message)
          print_good(err.backtrace)
        end
        
        buf.length
      end
    end 
    #
    # Create a session instance from a shell ID.
    #
    # @param conn [WinRM::Connection] A connection to a WinRM service
    # @param opts [Hash] Optional parameters to pass to the session object.
    def initialize(conn, opts = {})
      wrapper = WinrmSocketWrapper.new(conn, 'here',42)
      super(wrapper.lsock, opts)
    end
  end
end
