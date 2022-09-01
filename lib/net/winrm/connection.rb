##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'winrm'
require 'net/winrm/stdin_shell'
require 'net/winrm/rex_http_transport'

module Net
  module MsfWinRM
    # Connection to a WinRM service, using Rex sockets
    class RexWinRMConnection < WinRM::Connection
      # Factory class to create a shell of the appropriate type.
      # Subclassed to be able to provide a StdinShell
      class ShellFactory < WinRM::Shells::ShellFactory
        def create_shell(shell_type, shell_opts = {})
          args = [
            @connection_opts,
            @transport,
            @logger,
            shell_opts
          ]
          return StdinShell.new(*args) if shell_type == :stdin

          super(shell_type, shell_opts)
        end
      end

      # Creates a WinRM transport, subclassed to support Rex sockets
      class TransportFactory < WinRM::HTTP::TransportFactory
        def create_transport(connection_opts)
          raise NotImplementedError unless connection_opts[:transport] == :rexhttp

          super
        end

        private

        def init_rexhttp_transport(opts)
          RexHttpTransport.new(opts)
        end
      end

      # Provide an adapter for logging WinRM module messages to the MSF log
      class WinRMProxyLogger
        def error(msg)
          elog(msg, 'winrm')
        end

        def warn(msg)
          wlog(msg, 'winrm')
        end

        def info(msg)
          ilog(msg, 'winrm')
        end

        def debug(msg)
          dlog(msg, 'winrm')
        end
      end

      def shell_factory
        @shell_factory ||= ShellFactory.new(@connection_opts, transport, logger)
      end

      def transport
        @transport ||= begin
          transport_factory = TransportFactory.new
          transport_factory.create_transport(@connection_opts)
        end
      end

      def configure_logger
        @logger = WinRMProxyLogger.new
      end
    end
  end
end
