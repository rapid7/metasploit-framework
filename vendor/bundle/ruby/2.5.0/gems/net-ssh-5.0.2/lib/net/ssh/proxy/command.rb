require 'socket'
require 'rubygems'
require 'net/ssh/proxy/errors'
require 'net/ssh/ruby_compat'

module Net
  module SSH
    module Proxy

      # An implementation of a command proxy. To use it, instantiate it,
      # then pass the instantiated object via the :proxy key to
      # Net::SSH.start:
      #
      #   require 'net/ssh/proxy/command'
      #
      #   proxy = Net::SSH::Proxy::Command.new('ssh relay nc %h %p')
      #   Net::SSH.start('host', 'user', :proxy => proxy) do |ssh|
      #     ...
      #   end
      class Command
        # The command line template
        attr_reader :command_line_template

        # The command line for the session
        attr_reader :command_line

        # Timeout in seconds in open, defaults to 60
        attr_accessor :timeout

        # Create a new socket factory that tunnels via a command executed
        # with the user's shell, which is composed from the given command
        # template.  In the command template, `%h' will be substituted by
        # the host name to connect and `%p' by the port.
        def initialize(command_line_template)
          @command_line_template = command_line_template
          @command_line = nil
          @timeout = 60
        end

        # Return a new socket connected to the given host and port via the
        # proxy that was requested when the socket factory was instantiated.
        def open(host, port, connection_options = nil)
          command_line = @command_line_template.gsub(/%(.)/) {
            case $1
            when 'h'
              host
            when 'p'
              port.to_s
            when 'r'
              remote_user = connection_options && connection_options[:remote_user]
              if remote_user
                remote_user
              else
                raise ArgumentError, "remote user name not available"
              end
            when '%'
              '%'
            else
              raise ArgumentError, "unknown key: #{$1}"
            end
          }
          begin
            io = IO.popen(command_line, "r+")
            begin
              if result = IO.select([io], nil, [io], @timeout)
                if result.last.any? || io.eof?
                  raise "command failed"
                end
              else
                raise "command timed out"
              end
            rescue StandardError
              close_on_error(io)
              raise
            end
          rescue StandardError => e
            raise ConnectError, "#{e}: #{command_line}"
          end
          @command_line = command_line
          if Gem.win_platform?
            # read_nonblock and write_nonblock are not available on Windows
            # pipe. Use sysread and syswrite as a replacement works.
            def io.send(data, flag)
              syswrite(data)
            end

            def io.recv(size)
              sysread(size)
            end
          else
            def io.send(data, flag)
              begin
                result = write_nonblock(data)
              rescue IO::WaitWritable, Errno::EINTR
                IO.select(nil, [self])
                retry
              end
              result
            end

            def io.recv(size)
              begin
                result = read_nonblock(size)
              rescue IO::WaitReadable, Errno::EINTR
                timeout_in_seconds = 20
                if IO.select([self], nil, [self], timeout_in_seconds) == nil
                  raise "Unexpected spurious read wakeup"
                end
                retry
              end
              result
            end
          end
          io
        end

        def close_on_error(io)
          Process.kill('TERM', io.pid)
          Thread.new { io.close }
        end
      end
    end
  end
end
