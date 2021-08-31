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

      module PeerInfo
        include ::Rex::IO::Stream
        attr_accessor :peerinfo
        attr_accessor :localinfo
      end
      
      def initialize(shell, addr, port)
        self.shell = shell

        initialize_abstraction
        self.lsock.extend(PeerInfo)
        self.lsock.peerinfo = "[#{addr}]:#{port}"
        self.lsock.localinfo = "WinRM Client"
        prompt
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

      def prompt
        self.rsock.write("PS> ")
      end

      #
      # Read *length* bytes from the channel. If the operation times out, the data
      # that was read will be returned or nil if no data was read.
      #
      def read(length = nil)
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
        self.shell.run(buf) do |stdout, stderr|
          stdout&.each_line do |line|
            self.rsock.syswrite("#{line.rstrip!}\n")
          end
          self.rsock.syswrite(stderr)
        end

        prompt
        
        buf.length
      end
      protected
        attr_accessor :shell, :closed
    end 

    def commands
      {
        'help'       => 'Help menu',
        'background' => 'Backgrounds the current shell session',
        'sessions'   => 'Quickly switch to another session',
        'resource'   => 'Run a meta commands script stored in a local file',
        'irb'        => 'Open an interactive Ruby shell on the current session',
        'pry'        => 'Open the Pry debugger on the current session',
        'exit'       => 'Exit the shell'
      }
    end

    def cmd_exit
      wrapper.close
    end

    #
    # Create a session instance from a shell ID.
    #
    # @param shell [WinRM::Shells::Base] A WinRM shell object
    # @param opts [Hash] Optional parameters to pass to the session object.
    def initialize(shell, addr, port, opts = {})
      self.wrapper = WinrmSocketWrapper.new(shell, addr, port)
      super(self.wrapper.lsock, opts)
    end

protected
		attr_accessor :wrapper

  end
end
