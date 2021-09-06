##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'winrm'
require 'winrm/wsmv/write_stdin'

module Net
  module MsfWinRM
    class RexWinRMConnection < WinRM::Connection
      class MessageFactory < WinRM::PSRP::MessageFactory
        def self.create_pipeline_message(runspace_pool_id, pipeline_id, command)
          WinRM::PSRP::Message.new(
            runspace_pool_id,
            WinRM::PSRP::Message::MESSAGE_TYPES[:create_pipeline],
            XMLTemplate.render('create_pipeline', cmdlet: command[:cmdlet], args: command[:args]),
            pipeline_id
          )
        end
      end
    
      class ShellFactory < WinRM::Shells::ShellFactory
        class StdinShell < WinRM::Shells::Cmd
          class ReceiveResponseReader < WinRM::WSMV::ReceiveResponseReader
            def send_get_output_message(message)
              # Overridden without retry loop
              @transport.send_request(message)
            end
    
            # Reads streams and returns decoded output
            # @param wsmv_message [WinRM::WSMV::Base] A wsmv message to send to endpoint
            # @yieldparam [string] standard out response text
            # @yieldparam [string] standard error response text
            # @yieldreturn [WinRM::Output] The command output
            def read_output(wsmv_message)
              with_output do |output|
                read_response(wsmv_message, false) do |stream, doc|
                  handled_out = handle_stream(stream, output, doc)
                  yield handled_out if handled_out && block_given?
                end
              end
            end
    
            # Reads streams sent in one or more receive response messages
            # @param wsmv_message [WinRM::WSMV::Base] A wsmv message to send to endpoint
            # @param wait_for_done_state whether to poll for a CommandState of Done
            # @yieldparam [Hash] Hash representation of stream with type and text
            # @yieldparam [REXML::Document] Complete SOAP envelope returned to wsmv_message
            def read_response(wsmv_message, wait_for_done_state = false)
              resp_doc = nil
              until command_done?(resp_doc, wait_for_done_state)
                logger.debug('[WinRM] Waiting for output...')
                resp_doc = send_get_output_message(wsmv_message.build)
                logger.debug('[WinRM] Processing output')
                read_streams(resp_doc) do |stream|
                  yield stream, resp_doc
                end
              end
    
              if command_done?(resp_doc, true)
                raise EOFError.new('Program terminated')
              end
            end
          end
    
          # We create our own empty finalizers because the built-in one triggers a
          # request using the Rex HTTP client, which segfaults; possibly because it
          # creates a thread, or something else that is not allowed in a finalizer.
          # In this situation (observed only when the user quits MSF with active sessions),
          # we'll just let the shell continue.
          def remove_finalizer
          end
          def add_finalizer
          end
    
          def create_proc
            self.command_id = send_command("powershell.exe",[])
          end
    
          def with_command_shell(input, arguments = [])
            tries ||= 2
            send_stdin(input)
            yield shell_id, self.command_id
          rescue WinRM::WinRMWSManFault => e
            raise unless FAULTS_FOR_RESET.include?(e.fault_code) && (tries -= 1) > 0
    
            reset_on_error(e)
            retry
          end
    
          def cleanup_shell
            cleanup_command(command_id)
          end
    
          # Runs the specified command with optional arguments
          # @param block [&block] The optional callback for any realtime output
          # @yieldparam [string] standard out response text
          # @yieldparam [string] standard error response text
          # @yieldreturn [WinRM::Output] The command output
          def read_stdout(&block)
            open unless shell_id
            create_proc unless command_id
            begin
              response_reader.read_output(command_output_message(shell_id, command_id), &block)
            rescue WinRM::WinRMWSManFault => err
              if err.fault_code == '2150858793'
                yield nil, nil
              else
                raise
              end
            end
          end
    
          def send_stdin(input)
            open unless shell_id
            create_proc unless command_id
    
            stdin_msg = WinRM::WSMV::WriteStdin.new(
              connection_opts,
              shell_uri: shell_uri,
              shell_id: shell_id,
              command_id: command_id,
              stdin: input,
            )
            result = transport.send_request(stdin_msg.build)
            result
          rescue WinRM::WinRMWSManFault => e
            raise unless [ERROR_OPERATION_ABORTED, SHELL_NOT_FOUND].include?(e.fault_code)
          rescue WinRM::WinRMHTTPTransportError => t
            # dont let the cleanup raise so we dont lose any errors from the command
            logger.info("[WinRM] #{t.status_code} returned in cleanup with error: #{t.message}")
          end
    
    
          def response_reader
            @response_reader ||= ReceiveResponseReader.new(transport, logger)
          end
    
          def open_shell
            msg = WinRM::WSMV::CreateShell.new(connection_opts, shell_opts)
            resp_doc = transport.send_request(msg.build)
            self.owner = REXML::XPath.first(resp_doc, "//rsp:Owner").text
            REXML::XPath.first(resp_doc, "//*[@Name='ShellId']").text
          end
    
          attr_accessor :owner
    
          protected
            attr_accessor :command_id
        end
    
        def create_shell(shell_type, shell_opts = {})
          args = [
            @connection_opts,
            @transport,
            @logger
          ]
          return StdinShell.new(*args) if shell_type == :stdin
          super(shell_type, shell_opts)
        end
      end
    
      class TransportFactory < WinRM::HTTP::TransportFactory
        class RexHttpTransport < WinRM::HTTP::HttpTransport
          # rubocop:disable Lint/
          def initialize(opts)
            self.http_client = Rex::Proto::Http::Client.new(opts[:host], opts[:port], {}, opts[:ssl], opts[:ssl_version], opts[:proxies], opts[:user], opts[:password])
            @mutex = Mutex.new
            self.uri = opts[:uri]
            if opts[:realm]
              self.http_client.set_config('domain' => opts[:realm])
            end
          end

          def ntlm_transform_response(ntlm_client, response)
            # OMI server doesn't always respond to encrypted messages with encrypted responses over SSL
            return response.body if response.headers['Content-Type'].first =~ %r{\Aapplication\/soap\+xml}i
            return '' if response.body.empty?

            str = response.body.force_encoding('BINARY')
            str.sub!(%r{^.*Content-Type: application\/octet-stream\r\n(.*)--Encrypted.*$}m, '\1')
    
            signature = str[4..19]
            message = ntlm_client.session.unseal_message str[20..-1]
            if ntlm_client.session.verify_signature(signature, message)
              response.body = message
              return
            else
              raise WinRMHTTPTransportError, 'Could not decrypt NTLM message.'
            end
          end

          def ntlm_transform_request(ntlm_client, req)
            return req if !req.opts['data']
            req.opts['ctype'] = 'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"'
            data = req.opts['data']
            emessage = ntlm_client.session.seal_message data
            signature = ntlm_client.session.sign_message data
            edata = "\x10\x00\x00\x00#{signature}#{emessage}"

            req.opts['data'] = body(edata,data.bytesize)
            return req
          end

          def _send_request(message)
            @mutex.synchronize {
              opts = {
                'uri' => self.uri,
                'method' => 'POST',
                'agent' => 'Microsoft WinRM Client',
                'ctype' => 'application/soap+xml;charset=UTF-8',
              }
              if message
                opts['data'] = message
                opts['ntlm_transform_request'] = method(:ntlm_transform_request)
                opts['ntlm_transform_response'] = method(:ntlm_transform_response)
              end
              request = self.http_client.request_cgi(opts)
              response = self.http_client.send_recv(request,-1,true)
              if response
                WinRM::ResponseHandler.new(response.body, response.code).parse_to_xml
              else
                raise WinRM::WinRMHTTPTransportError.new("No response")
              end
            }
          end

          def send_request(message)
            unless self.first_request_sent
              _send_request(nil)
              self.first_request_sent = true
            end
            _send_request(message)
          end
          protected
            attr_accessor :http_client, :uri

            # Need to send an empty first request to potentially set up an encryption
            # channel - required if allowUnencrypted is set to false, which is the case
            # by default
            attr_accessor :first_request_sent
        end
    
        def create_transport(connection_opts)
          raise NotImplementedError unless connection_opts[:transport] == :rex
    
          super
        end
    
        private
    
        def init_rex_transport(opts)
          RexHttpTransport.new(opts)
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
    end
  end
end
