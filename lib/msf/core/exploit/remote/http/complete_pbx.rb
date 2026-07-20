# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        #
        # Shared routines for Xorcom CompletePBX modules
        #
        module CompletePBX
          # Probe root page and return appropriate CheckCode
          # @return [Msf::Exploit::CheckCode]
          def completepbx?
            vprint_status('Checking if the target is running CompletePBX...')
            res = send_request_cgi('uri' => normalize_uri(target_uri.path), 'method' => 'GET')
            return Exploit::CheckCode::Unknown('No response from target.') unless res
            return Exploit::CheckCode::Unknown("Unexpected HTTP response code: #{res.code}") unless res.code == 200

            doc = res.get_html_document
            if doc.at('//meta[@name="description"][@content="CompletePBX"]') ||
               doc.at('//meta[@name="application-name"][@content="Ombutel"]')
              vprint_good("Detected CompletePBX on #{peer}")
              return Exploit::CheckCode::Appears
            end

            Exploit::CheckCode::Safe('Target does not appear to be running CompletePBX.')
          end

          # Authenticate with supplied credentials and return the session cookie.
          #
          # @param username [String] CompletePBX username
          # @param password [String] CompletePBX password
          # @return [String]         the "sid=..." cookie value
          # @raise  [Msf::Exploit::Failure] on authentication failure
          #
          def completepbx_login(username, password)
            vprint_status("Attempting authentication with username: #{username}")

            res = send_request_cgi(
              'uri' => normalize_uri(target_uri.path, 'login'),
              'method' => 'POST',
              'ctype' => 'application/x-www-form-urlencoded',
              'vars_post' => { 'userid' => username, 'userpass' => password }
            )
            unless res&.code == 200
              vprint_error('Authentication failed')
              fail_with(Msf::Module::Failure::NoAccess, 'Authentication failed')
            end

            sid = res.get_cookies.scan(/sid=[a-f0-9]+/).first
            fail_with(Msf::Module::Failure::NoAccess, 'No session ID received') unless sid

            vprint_good("Authentication successful! Session ID: #{sid}")
            sid
          end
        end
      end
    end
  end
end
