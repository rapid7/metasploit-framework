
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # The Zabbix HTTP LoginScanner class provides methods to do login routines
      # for Zabbix 2.4 and 2.2 as well as versions 3, 4, and 5.
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

            if res.body.to_s !~ /Zabbix ([^\s]+) Copyright .* by Zabbix/m # Regex check for older versions of Zabbix prior to version 3.
              if res.body.to_s !~ /<a target="_blank" class="grey link-alt" href="http[sS]{0,1}:\/\/www\.zabbix\.com\/documentation\/(\d+\.\d+)\/">Help<\/a>/m
	              return "Unexpected HTTP body (is this really Zabbix?)" # If both the regex for the old and new versions
                                                                       # fail to match, the target likely isn't Zabbix.
              end
            end

            self.version = $1

          rescue ::EOFError, Errno::ETIMEDOUT, OpenSSL::SSL::SSLError, Rex::ConnectionError, ::Timeout::Error
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
          if res && res.get_cookies =~ /(zbx_session(?:id)?=\w+(?:%3D){0,2};)/i
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


        def perform_login_attempt(url)
          opts = {
            'uri'     => normalize_uri(url),
            'method'  => 'GET',
            'headers' => {
              'Cookie'  => "#{self.zsession}"
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
          begin
            res = try_credential(credential)

            if res && res.code == 302
              res = perform_login_attempt('profile.php') # profile.php exists in Zabbix versions up to Zabbix 5.x
              if (res && res.code == 200 && res.body.to_s =~ /<title>.*: User profile<\/title>/)
                return {:status => Metasploit::Model::Login::Status::SUCCESSFUL, :proof => res.body}
              else
                res = perform_login_attempt('/zabbix.php?action=userprofile.edit') # On version 5.x and later of Zabbix, profile.php was replaced with /zabbix.php?action=userprofile.edit
                if (res && res.code == 200 && res.body.to_s =~ /<title>.*: User profile<\/title>/)
                  return {:status => Metasploit::Model::Login::Status::SUCCESSFUL, :proof => res.body}
                end
              end
            end

            {:status => Metasploit::Model::Login::Status::INCORRECT, :proof => res.body}

          rescue ::EOFError, Errno::ETIMEDOUT, Errno::ECONNRESET, Rex::ConnectionError, OpenSSL::SSL::SSLError, ::Timeout::Error => e
            return {:status => Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e}
          end
        end

      end
    end
  end
end

