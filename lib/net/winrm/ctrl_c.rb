require 'winrm/wsmv/base'

module Net
  module MsfWinRM
    # Represents a WinRM Ctrl+C signal message
    class CtrlC < WinRM::WSMV::Base
      # Initializes the CtrlC message
      #
      # @param session_opts [Hash] Options for WinRM session
      # @param opts [Hash] Additional options including :shell_id and :command_id
      # @option opts [String] :shell_id The WinRM shell identifier
      # @option opts [String] :command_id The WinRM command identifier
      # @option opts [String] :shell_uri Optional URI for shell
      #
      # @raise [ArgumentError] If :shell_id or :command_id is missing
      def initialize(session_opts, opts)
        validate_options(opts)
        super()
        @session_opts = session_opts
        @shell_id = opts[:shell_id]
        @command_id = opts[:command_id]
        @shell_uri = opts[:shell_uri] || RESOURCE_URI_CMD
      end

      # Sends the Ctrl+C signal
      #
      # @param async [Boolean] Whether to send signal asynchronously (default: false)
      # @param timeout [Integer] Timeout in seconds for the operation (default: nil)
      #
      # @return [Boolean] True if signal sent successfully, false otherwise
      def send_signal(async: false, timeout: nil)
        request = build_request
        response = send_request(request, async: async, timeout: timeout)
        handle_response(response)
      end

      private

      # Validates the options passed during initialization
      def validate_options(opts)
        raise ArgumentError, 'opts[:shell_id] is required' unless opts[:shell_id]
        raise ArgumentError, 'opts[:command_id] is required' unless opts[:command_id]
      end

      # Builds the XML request header
      def build_request
        Gyoku.xml(header: build_header, body: build_body)
      end

      # Builds the XML header for Ctrl+C signal
      def build_header
        [].tap do |header|
          header << shared_headers(@session_opts)
          header << resource_uri_shell(@shell_uri)
          header << action_signal
          header << selector_shell_id(@shell_id)
        end
      end

      # Builds the XML body for Ctrl+C signal
      def build_body
        Nokogiri::XML::Builder.new do |xml|
          xml.Signal('xmlns' => NS_WIN_SHELL, 'CommandId' => @command_id) do
            xml.Code('xmlns' => NS_WIN_SHELL) do
              xml.text 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c'
            end
          end
        end.to_xml
      end

      # Handles the response from WinRM server
      #
      # @param response [Object] Response object from WinRM server
      #
      # @raise [WinRMError] If response indicates failure
      #
      # @return [Boolean] True if response indicates success, false otherwise
      def handle_response(response)
        raise WinRMError, "WinRM request failed with status: #{response.status}" unless response.status == 200

        true
      end
    end
  end
end
