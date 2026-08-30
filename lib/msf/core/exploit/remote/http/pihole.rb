# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of interacting with pihole installations
        module Pihole
          include Msf::Exploit::Remote::HttpClient

          def initialize(info = {})
            super

            register_options(
              [
                OptString.new('PASSWORD', [ false, 'Password for Pi-Hole interface', ''])
              ], Msf::Exploit::Remote::HTTP::Pihole
            )
          end

          # Extracts the Pihole version information from the admin page
          #
          # @return [(String, String, String),nil] Pihole versions if found (version, web_version, ftl_version), nil otherwise
          def get_versions
            res = send_request_cgi(
              'uri' => normalize_uri(target_uri.path, 'admin', 'index.php'),
              'method' => 'GET',
              'keep_cookies' => true
            )
            return nil if res.nil? || res.code != 200

            # Verified against:
            # (current) 5.7, 5.12.1, 5.9
            # 5.2.2, 5.2.2, 5.3.3
            # 4.4, 4.3.3, 4.3.1
            # 4.3.2, 4.3, 4.3.1

            unless %r{<(?:strong|b)>Pi-hole(?: Version)?\s*</(?:strong|b)>\s*(?:<a .*?>)?v(?<version>[\d.]{1,8})\s*<}m =~ res.body
              # vDev versions
              %r{<(?:strong|b)>Pi-hole(?: Version)?\s*</(?:strong|b)>\s*(?:<a .*?>)?vDev \(\w+, v(?<version>[\d.]{1,8})[\w-]+\)<}m =~ res.body
            end
            %r{<(?:strong|b)>Web Interface(?: Version)?\s*</(?:strong|b)>\s*(?:<a .*?>)?v(?<web_version>[\d.]{1,8})\s*<}m =~ res.body
            %r{<(?:strong|b)>FTL(?: Version)?\s*</(?:strong|b)>\s*(?:<a .*?>)?v(?<ftl_version>[\d.]{1,8})\s*<}m =~ res.body
            return version, web_version, ftl_version
          end

          # Performs a login to pihole
          #
          # @param pass [String] Password
          # @return [String,nil] cookie if login was successful, nil otherwise
          def login(password)
            vprint_status('Attempting login.')
            res = send_request_cgi(
              'uri' => normalize_uri(target_uri.path, 'admin', 'index.php'),
              'vars_get' => {
                'login' => ''
              },
              'vars_post' => {
                'pw' => password
              },
              'method' => 'POST',
              'keep_cookies' => true
            )
            if res && res.code == 200 && res.body.exclude?('Sign in to start your session')
              return res.get_cookies
            end

            vprint_error('Incorrect Password')
            nil
          end

          # Performs a gravity update
          #
          # @return [HTTPResponse,nil] HTTPResponse
          def update_gravity
            vprint_status('Forcing gravity pull')
            send_request_cgi(
              'uri' => normalize_uri(target_uri.path, 'admin', 'scripts', 'pi-hole', 'php', 'gravity.sh.php'),
              'keep_cookies' => true
            )
          end

          # Attempts to retrieve a CSRF token from the tab.
          #
          # @param tab [String] Which tab to load on the admin/settings page
          # @return [String,nil] String of the token, nil otherwise
          def get_token(tab)
            res = send_request_cgi(
              'uri' => normalize_uri(target_uri.path, 'admin', 'settings.php'),
              'vars_get' => {
                'tab' => tab
              },
              'keep_cookies' => true
            )
            return nil unless res or res.code == 200
            # <input type="hidden" name="token" value="t51q3YuxWT873Nn+6lCyMG4Lg840gRCgu03akuXcvTk=">
            # may also include /
            # from version 3.3 <div id="token" hidden>f5al5pNfFj9YOCSdX159tXjttdHUOAuxOJDgwcgnUHs=</div>
            if (%r{name="token" value="(?<token>[\w+=/]+)">} =~ res.body ||
              %r{div id="token" hidden>(?<token>[\w+=/]+)</div>} =~ res.body)
              return token
            end

            nil
          end
        end
      end
    end
  end
end
