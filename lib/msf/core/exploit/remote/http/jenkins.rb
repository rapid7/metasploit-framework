# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of logging into Jenkins
        module Jenkins
          # Returns the Jenkins version.
          #
          # @return [String] Jenkins version.
          # @return [NilClass] No Jenkins version found.
          def jenkins_version
            uri = normalize_uri(target_uri.path)
            res = send_request_cgi({ 'uri' => uri })

            unless res
              return nil
            end

            # shortcut for new versions such as 2.426.2 and 2.440
            return res.headers['X-Jenkins'] if res.headers['X-Jenkins']

            html = res.get_html_document
            version_attribute = html.at('body').attributes['data-version']
            version = version_attribute ? version_attribute.value : ''
            version.scan(/jenkins-([\d.]+)/).flatten.first
          end

          # This method takes a target URI and makes a request to verify if logging in is possible,
          # otherwise it will fail gracefully
          #
          # @param [URI, String] target_uri The targets URI
          # @return [String] URI for successful login
          def jenkins_uri_check(target_uri, keep_cookies: false)
            # if keep_cookies is true we get the first cookie that's needed by newer Jenkins versions
            res = send_request_cgi({ 'uri' => normalize_uri(target_uri, 'login'), 'keep_cookies' => keep_cookies })
            fail_with(Msf::Module::Failure::UnexpectedReply, 'Unexpected reply from server') unless res&.code == 200
            if res.body =~ /action="(j_([a-z0-9_]+))"/
              uri = Regexp.last_match(1)
            else
              fail_with(Msf::Module::Failure::UnexpectedReply, 'Failed to identify the login resource.')
            end

            normalize_uri(target_uri, uri)
          end

          # This method takes a username and password and a target URI
          # then attempts to login to Jenkins and will either fail with appropriate errors
          #
          # @param [String] username The username for login credentials
          # @param [String] password The password for login credentials
          # @return [Array] [status, proof] The result of the login attempt
          def jenkins_login(username, password, target_uri = nil)
            begin
              request = {
                'vars_post' =>
                  {
                    'j_username' => username,
                    'j_password' => password,
                    'Submit' => 'log in'
                  }
              }

              if block_given?
                res = yield request
              else
                res = send_request_cgi({
                  'method' => 'POST',
                  'uri' => normalize_uri(target_uri),
                  'keep_cookies' => true,
                  'vars_post' => request['vars_post']
                })
              end

              if res && res.headers['location'] && !res.headers['location'].include?('loginError')
                status = Metasploit::Model::Login::Status::SUCCESSFUL
                proof = res.headers
              else
                status = Metasploit::Model::Login::Status::INCORRECT
                proof = res
              end
            rescue ::EOFError, Errno::ETIMEDOUT, Errno::ECONNRESET, Rex::ConnectionError, OpenSSL::SSL::SSLError, ::Timeout::Error => e
              status = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
              proof = e
            end

            [status, proof]
          end
        end
      end
    end
  end
end
