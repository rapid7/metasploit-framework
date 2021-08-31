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

      attr_accessor :shell_id, :exploit_module

      module PeerInfo
        include ::Rex::IO::Stream
        attr_accessor :peerinfo
        attr_accessor :localinfo
      end
      
      def initialize(shell_id, exploit_module, addr, port)
        self.shell_id = shell_id
        self.exploit_module = exploit_module

        initialize_abstraction
        self.lsock.extend(PeerInfo)
        self.lsock.peerinfo = "[#{addr}]:#{port}"
        self.lsock.localinfo = "[127.0.0.1]"
      end
     
     def closed?
        false # TODO
      end

      def close
        print_good "proof 3"
        cleanup_abstraction
      end

      def close_write
        if closed?
          raise IOError, 'Channel has been closed.', caller
        end
        #TODO
      end

      #
      # Read *length* bytes from the channel. If the operation times out, the data
      # that was read will be returned or nil if no data was read.
      #
      def read(length = nil)
        print_good "proof 2"
        raise IOError, 'Proof 2'
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

        
        
        print_good("Running #{buf} with #{self.shell_id}")
        timeout=20
        begin
          resp = exploit_module.send_winrm_request(exploit_module.winrm_cmd_msg(buf, self.shell_id),timeout)
          print_good(resp)
          cmd_id = exploit_module.winrm_get_cmd_id(resp)
          print_good("Got command with #{cmd_id}")
          resp = exploit_module.send_winrm_request(exploit_module.winrm_cmd_recv_msg(self.shell_id,cmd_id),timeout)
          streams = exploit_module.winrm_get_cmd_streams(resp)
          print_good("Got streams")
          resp = exploit_module.send_winrm_request(exploit_module.winrm_terminate_cmd_msg(self.shell_id,cmd_id),timeout)
          print_good(streams['stdout'])
        rescue Exception => error
          print_good(error.message)
          print_good(error.backtrace)
          self.rsock.syswrite("got em")
        end

        buf.length
      end
    end 
    #
    # Create a session instance from a shell ID.
    #
    # @param shell_id [String] The WinRM-specified ID of the shell object
    # @param opts [Hash] Optional parameters to pass to the session object.
    def initialize(shell_id, exploit_module, opts = {})
      wrapper = WinrmSocketWrapper.new(shell_id, exploit_module, 'here',42)
      super(wrapper.lsock, opts)
    end

    

  end
end
