require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      class Ivanti < HTTP

        def create_user_request(username, password, protocol, peer)
          {
            'method' => 'POST',
            'uri' => normalize_uri('/dana-na/auth/url_default/login.cgi'),
            'ctype' => 'application/x-www-form-urlencoded',
            'headers' =>
            {
        'Cache-Control'=> 'max-age=0',
        'Sec-Ch-Ua'=> '"Chromium";v="131", "Not_A Brand";v="24"',
        'Sec-Ch-Ua-Mobile'=> '?0',
        'Sec-Ch-Ua-Platform'=> 'Linux',
        'Accept-Language'=> 'en-US,en;q=0.9',
        'Origin'=> "#{protocol}://#{peer}",
        'Upgrade-Insecure-Requests'=> '1',
        'Accept'=> 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site'=> 'same-origin',
        'Sec-Fetch-Mode'=> 'navigate',
        'Sec-Fetch-User'=> '?1',
        'Sec-Fetch-Dest'=> 'document',
        'Referer'=> "#{protocol}://#{peer}/dana-na/auth/url_default/welcome.cgi",
        'Accept-Encoding'=> 'gzip, deflate, br',
        'Priority'=> 'u=0, i'
            },
            'vars_post' =>
              {
                tz_offset: '',
                win11: '',
                clientMAC: '',
                username: username,
                password: password,
                realm: 'Users',
                btnSubmit: 'Sign+In'
              },
            'encode_params' => false
          }
        end

        def do_logout(cookies)
          logout_res = send_request({'uri'=>normalize_uri('/dana-na/auth/logout.cgi?delivery=psal'), 'cookie' => cookies})
          logout_res
        end


        def do_login(username, password)
          protocol = ssl ? 'https' : 'http'
          peer = "#{host}:#{port}"
          user_req = create_user_request(username, password, protocol, peer)
          begin
            res = send_request(user_req)
          rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error, ::EOFError => e
            return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof:e }
          end
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'Unable to connect to the Ivanti service' } if res.nil?
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: "Received an unexpected status code: #{res.code}" } if res.code != 302
          return { status: ::Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: "Unexpected response"} if res.blank?
         
          if res.headers['location'] == '/dana-na/auth/url_default/welcome.cgi?p=ip%2Dblocked'
            sleep(2*60) # 2 minutes 
            res = send_request(user_req)
          end
         
          return { status: ::Metasploit::Model::Login::Status::SUCCESSFUL, proof:res.to_s} if res.headers['location'] == '/dana-na/auth/url_default/welcome.cgi?p=user%2Dconfirm' 

          if res.headers['location'] == '/dana/home/starter0.cgi?check=yes'
            do_logout(res.get_cookies)
            return { status: ::Metasploit::Model::Login::Status::SUCCESSFUL	, proof: res.to_s}
          else
            return {status: ::Metasploit::Model::Login::Status::INCORRECT, proof: res.to_s }
          end
        end

        # Attempts to login to the server.
        #
        # @param [Metasploit::Framework::Credential] credential The credential information.
        # @return [Result] A Result object indicating success or failure
        def attempt_login(credential)
          # focus on creating Result object, pass it to #login routine and return Result object
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
