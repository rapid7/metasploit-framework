require 'winrm'

module Net
  module MsfWinRM
    # Transport for communicating to a WinRM service, using Rex sockets
    class RexHttpTransport < WinRM::HTTP::HttpTransport
      # rubocop:disable Lint/
      def initialize(opts)
        self.http_client = Rex::Proto::Http::Client.new(opts[:host], opts[:port], {}, opts[:ssl], opts[:ssl_version], opts[:proxies], opts[:user], opts[:password])
        self.timeout = opts[:timeout]
        @mutex = Mutex.new
        self.uri = opts[:uri]
        if opts[:realm]
          http_client.set_config('domain' => opts[:realm])
        end
      end

      def peerinfo
        if http_client && http_client.conn
          http_client.conn.peerinfo
        end
      end

      def localinfo
        if http_client && http_client.conn
          http_client.conn.localinfo
        end
      end

      # Performs decryption of the stream coming from the HTTP client
      def ntlm_transform_response(ntlm_client, response)
        # OMI server doesn't always respond to encrypted messages with encrypted responses over SSL
        return unless response
        return if response.headers['Content-Type'] && response.headers['Content-Type'].first =~ (%r{\Aapplication/soap\+xml}i)
        return if response.body.empty?

        str = response.body.force_encoding('BINARY')
        str.sub!(%r{^.*Content-Type: application/octet-stream\r\n(.*)--Encrypted.*$}m, '\1')

        signature = str[4..19]
        message = ntlm_client.session.unseal_message(str[20..-1])
        if ntlm_client.session.verify_signature(signature, message)
          response.body = message
          return
        else
          raise WinRM::WinRMHTTPTransportError, 'Could not decrypt NTLM message.'
        end
      end

      # Performs encryption of the stream being sent to the HTTP client
      def ntlm_transform_request(ntlm_client, req)
        return req if !req.opts['data']
        opts = req.opts.dup

        opts['ctype'] = 'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"'
        data = opts['data']
        emessage = ntlm_client.session.seal_message(data)
        signature = ntlm_client.session.sign_message(data)
        edata = "\x10\x00\x00\x00#{signature}#{emessage}"

        opts['data'] = body(edata, data.bytesize)
        Rex::Proto::Http::ClientRequest.new(opts)
      end

      def _send_request(message)
        @mutex.synchronize do
          opts = {
            'uri' => uri,
            'method' => 'POST',
            'agent' => 'Microsoft WinRM Client',
            'ctype' => 'application/soap+xml;charset=UTF-8',
            'no_body_for_auth' => true
          }
          if message
            opts['data'] = message
            opts['ntlm_transform_request'] = method(:ntlm_transform_request)
            opts['ntlm_transform_response'] = method(:ntlm_transform_response)
          end
          request = http_client.request_cgi(opts)
          response = http_client.send_recv(request, timeout, true)
          if response
            WinRM::ResponseHandler.new(response.body, response.code).parse_to_xml
          else
            raise WinRM::WinRMHTTPTransportError, 'No response'
          end
        end
      end

      def send_request(message)
        _send_request(message)
      end

      protected

      attr_accessor :http_client, :uri, :timeout
    end
  end
end
