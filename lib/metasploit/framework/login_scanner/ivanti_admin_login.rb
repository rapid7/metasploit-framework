require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      class IvantiAdmin < HTTP

        def create_admin_request(username, password, token, protocol, peer)
          {
            'method' => 'POST',
            'uri' => normalize_uri('/dana-na/auth/url_admin/login.cgi'),
            'ctype' => 'application/x-www-form-urlencoded',
            'headers' =>
            {
              'Origin'=> "#{protocol}://#{peer}",
              'Referer'=> "#{protocol}://#{peer}/dana-na/auth/url_admin/welcome.cgi",
            },
            'vars_post' => {
              tz_offset: '60',
              xsauth_token: token,
              username: username,
              password: password,
              realm: "Admin+Users",
              btnSubmit: "Sign+In"

            },
            'encode_params' => false
          }
        end

        def do_logout(cookies)
          admin_page_res = send_request({ 'method' => 'GET', 'uri' => normalize_uri('/dana-admin/misc/admin.cgi?'), 'cookie' => cookies  })
          admin_page_s = admin_page_res.to_s
          re = /xsauth\=[a-z0-9]{32}/
          xsauth = re.match(admin_page_s)[0]
          logout_res = send_request({  'method' => 'GET', 'uri' => normalize_uri('/dana-na/auth/logout.cgi?'+xsauth), 'cookie' => cookies   })
          logout_res
        end

        def get_token 
          res = send_request({
            'uri'=>normalize_uri('/dana-na/auth/url_admin/welcome.cgi'),
          })
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to the Ivanti service' } if res.nil?
          
          html_document = res.get_html_document
          token = html_document.xpath('//input[@id="xsauth_token"]/@value').text
          token

        end

        def do_login(username, password)
          token = get_token

          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to the TeamCity service' } if token.blank?
          protocol = ssl ? 'https' : 'http'
          peer = "#{host}:#{port}"
          admin_req = create_admin_request(username, password, token, protocol, peer)
          begin
            res = send_request(admin_req)
          rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error, ::EOFError => e
           return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e }
          end
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to the Ivanti service' } if res.nil?
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: "Received an unexpected status code: #{res.code}" } if res.code != 302
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: "Unexpected response"} if res.blank?

          return { status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof: res.to_s} if res.headers['location'] == '/dana-na/auth/url_admin/welcome.cgi?p=admin%2Dconfirm'

          if res.headers['location'] == '/dana-admin/misc/admin.cgi'
            do_logout(res.get_cookies)
            return { status: ::Metasploit::Model::Login::Status::SUCCESSFUL	, proof: res.to_s} 
          end
          
          return {status: ::Metasploit::Model::Login::Status::INCORRECT, proof: res.to_s }

        end
        
        def attempt_login(credential)
          result_options = {
            credential: credential,
            host: @host,
            port: @port,
            protocol: 'tcp',
            service_name: 'ivanti'
          }
          login_result = do_login(credential.public, credential.private)
          result_options.merge!(login_result)
          Result.new(result_options)
        end

      end
    end
  end
end
