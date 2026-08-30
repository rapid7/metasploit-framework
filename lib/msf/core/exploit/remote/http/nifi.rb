# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of interacting with Apache NiFi installations
        module Nifi
          include Msf::Exploit::Remote::HttpClient
          include Msf::Exploit::Remote::HTTP::Nifi::Auth
          include Msf::Exploit::Remote::HTTP::Nifi::Processor
          include Msf::Exploit::Remote::HTTP::Nifi::Dbconnectionpool

          def initialize(info = {})
            super

            register_options(
              [
                Msf::Opt::RPORT(8443),
                Msf::OptString.new('TARGETURI', [ true, 'The URI of the Apache NiFi Application', '/']),
                Msf::OptString.new('USERNAME', [false, 'Username to authenticate with']),
                Msf::OptString.new('PASSWORD', [false, 'Password to authenticate with']),
                Msf::OptString.new('BEARER-TOKEN', [false, 'JWT authenticate with']),
              ], Msf::Exploit::Remote::HTTP::Nifi
            )

            register_advanced_options([
              Msf::OptBool.new('SSL', [true, 'Negotiate SSL connection', true])
            ])
          end

          # Find the version number of the Apache NiFi system based on JS calls on the nifi/ page.
          #
          # @return [Gem::Version] version number of the system, or nil on error
          def get_version
            vprint_status('Attempting to retrieve version number')
            res = send_request_cgi!(
              'uri' => normalize_uri(target_uri.path, 'nifi/')
            )

            if res.nil?
              print_bad("#{peer} - Could not connect to web service - no response")
              return nil
            end

            unless res.code == 200
              print_bad("#{peer} - Unexpected Response Code (response code: #{res.code})")
              return nil
            end

            return Rex::Version.new(Regexp.last_match(1)) if res.body =~ %r{js/nf/nf-namespace\.js\?([\d.]*)">}

            nil
          end

          # Fetch the root process group's UUID
          #
          # @param token [String] The bearer token from a valid login, or nil for no Authorization headers
          # @return [String] The UUID of the root process group
          def fetch_root_process_group(token)
            vprint_status('Attempting to retrieve root process group')
            opts = {
              'method' => 'GET',
              'uri' => normalize_uri(target_uri.path, 'nifi-api', 'process-groups', 'root')
            }
            opts['headers'] = { 'Authorization' => "Bearer #{token}" } if token
            res = send_request_cgi(opts)
            
            if res.nil?
              print_bad("#{peer} - Could not connect to web service - no response")
              return nil
            end

            unless res.code == 200
              print_bad("Unexpected response code: #{res.code}")
              return nil
            end
            res.get_json_document['id']
          end
        end
      end
    end
  end
end
