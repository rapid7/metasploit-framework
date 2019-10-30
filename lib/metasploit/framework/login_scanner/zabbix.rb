
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # The Zabbix HTTP LoginScanner class provides methods to do login routines
      # for Zabbix 2.4 and 2.2
      class Zabbix < HTTP

        DEFAULT_PORT  = 80
        PRIVATE_TYPES = [ :password ]

        # @!attribute version
        #   @return [String] Product version
        attr_accessor :version

        # @!attribute zsession
        #   @return [String] Cookie session
        attr_accessor :zsession

        # Decides which login routine and returns the results
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Result]
        def attempt_login(credential)
          result_opts = { credential: credential }

          begin
            status = try_login(credential)
            result_opts.merge!(status)
          rescue ::EOFError, Rex::ConnectionError, ::Timeout::Error => e
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          end

          Result.new(result_opts)
        end


        # (see Base#check_setup)
        def check_setup
          begin
            res = send_request({'uri' => normalize_uri('/')})
            return "Connection failed" if res.nil?

            if res.code != 200
              return "Unexpected HTTP response code #{res.code} (is this really Zabbix?)"
            end

            if res.body.to_s !~ /Zabbix ([^\s]+) Copyright .* by Zabbix/m
              return "Unexpected HTTP body (is this really Zabbix?)"
            end

            self.version = $1

          rescue ::EOFError, Errno::ETIMEDOUT, Rex::ConnectionError, ::Timeout::Error
            return "Unable to connect to target"
          end

          false
        end

        # Sends a HTTP request with Rex
        #
        # @param (see Rex::Proto::Http::Resquest#request_raw)
        # @return [Rex::Proto::Http::Response] The HTTP response
        def send_request(opts)
          cli = Rex::Proto::Http::Client.new(host, port, {'Msf' => framework, 'MsfExploit' => self}, ssl, ssl_version, proxies, http_username, http_password)
          configure_http_client(cli)
          cli.connect
          req = cli.request_raw(opts)
          res = cli.send_recv(req)

          # Found a cookie? Set it. We're going to need it.
          if res && res.get_cookies =~ /zbx_sessionid=(\w*);/i
            self.zsession = $1
          end

          res
        end

        # Sends a login request
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Rex::Proto::Http::Response] The HTTP auth response
        def try_credential(credential)

          data  = "request="
          data << "&name=#{Rex::Text.uri_encode(credential.public)}"
          data << "&password=#{Rex::Text.uri_encode(credential.private)}"
          data << "&autologin=1"
          data << "&enter=Sign%20in"

          opts = {
            'uri'     => normalize_uri('index.php'),
            'method'  => 'POST',
            'data'    => data,
            'headers' => {
              'Content-Type'   => 'application/x-www-form-urlencoded'
            }
          }

          send_request(opts)
        end


        # Tries to login to Zabbix
        #
        # @param credential [Metasploit::Framework::Credential] The credential object
        # @return [Hash]
        #   * :status [Metasploit::Model::Login::Status]
        #   * :proof [String] the HTTP response body
        def try_login(credential)
          res = try_credential(credential)
          if res && res.code == 302
            opts = {
              'uri'     => normalize_uri('profile.php'),
              'method'  => 'GET',
              'headers' => {
                'Cookie'  => "zbx_sessionid=#{self.zsession}"
              }
            }
            res = send_request(opts)
            if (res && res.code == 200 && res.body.to_s =~ /<title>Zabbix .*: User profile<\/title>/)
              return {:status => Metasploit::Model::Login::Status::SUCCESSFUL, :proof => res.body}
            end
          end

          {:status => Metasploit::Model::Login::Status::INCORRECT, :proof => res.body}
        end

      end
    end
  end
end

