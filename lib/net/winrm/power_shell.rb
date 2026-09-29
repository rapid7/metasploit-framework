# frozen_string_literal: true

require 'winrm'

module Net
  module MsfWinRM
    # WinRM PowerShell shell for Rex HTTP backed connections.
    class PowerShell < WinRM::Shells::Powershell
      def initialize(connection_opts, transport, logger, _shell_opts = {})
        super(connection_opts, transport, logger)
      end

      # See StdinShell for context. The upstream finalizer can issue a request
      # through the Rex HTTP client while Ruby is finalizing objects.
      def remove_finalizer; end

      def add_finalizer; end
    end
  end
end
