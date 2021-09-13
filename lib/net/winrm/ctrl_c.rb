# WSMV message to send a Ctrl+C signal to a remote shell
require 'winrm/wsmv/base'
module Net
  module MsfWinRM
    # A WinRM Ctrl+C signal message
    class CtrlC < WinRM::WSMV::Base
      def initialize(session_opts, opts)
        raise 'opts[:shell_id] is required' unless opts[:shell_id]
        raise 'opts[:command_id] is required' unless opts[:command_id]

        super()

        @session_opts = session_opts
        @shell_id = opts[:shell_id]
        @command_id = opts[:command_id]
        @shell_uri = opts[:shell_uri] || RESOURCE_URI_CMD
      end

      protected

      def create_header(header)
        header << Gyoku.xml(ctrl_c_header)
      end

      def create_body(body)
        body.tag!("#{NS_WIN_SHELL}:Signal", 'CommandId' => @command_id) do |cl|
          cl << Gyoku.xml(ctrl_c_body)
        end
      end

      private

      def ctrl_c_header
        merge_headers(shared_headers(@session_opts),
                      resource_uri_shell(@shell_uri),
                      action_signal,
                      selector_shell_id(@shell_id))
      end

      def ctrl_c_body
        {
          "#{NS_WIN_SHELL}:Code" =>
            'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c'
        }
      end
    end
  end
end
