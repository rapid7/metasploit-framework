module Msf
  class Exploit
    class Remote
      module HTTP
        module Beyondtrust
          include Msf::Exploit::Remote::HttpClient
      
          def initialize(info={})
            super
          end

          def get_version
            res = send_request_cgi(
              'method' => 'GET',
              'uri' => normalize_uri(target_uri.path, 'get_rdf'),
              'vars_get' => {
                'comp' => 'sdcust',
                'locale_code' => 'en-us'
              }
            ) 
            return nil unless res&.code == 200

            header = res.body.match(/^(0 Successful\n.+\n\d+\n)/)
            
            return nil unless header
            
            brdf_data = res.body[header[1].length..]
            
            return nil unless brdf_data.include?('Thank you for using BeyondTrust')

            magic, _, _, prod_version_tag1, file_version_data_len, file_version_tag2 = brdf_data.unpack('NCvCCC')

            return nil unless magic == 0x42524446 # "BRDF" in ASCII
            return nil unless prod_version_tag1 == 0x91
            return nil unless file_version_tag2 == 0x81

            brdf_data[10, file_version_data_len - 1]
          end

          # We need to know the target sites company name, or FQDN, in order to successfully establish a WebSocket connection.
          # We first favor the user setting either the TargetCompanyName or TargetServerFQDN options. If not set we then try
          # an undocumented API endpoint /get_mech_list, that should return the target site company name. Finally, we fall
          # back on the /download_client_connector endpoint which will also report a servername and site FQDN.
          def get_site_info
            if !datastore['TargetCompanyName'].blank? || !datastore['TargetServerFQDN'].blank?
              return {
                company: datastore['TargetCompanyName'],
                server: datastore['TargetServerFQDN']
              }
            end

            site_info = get_site_info_via_mech_list

            return site_info unless site_info.nil?

            get_site_info_via_download_client_connector
          end

          # The internal undocumented API located at the /get_mech_list endpoint will return the company name
          # of the target site. We try version=3 (JSON, newer instances) first, then fall back to version=2
          # (semicolon-separated key=value pairs, for older instances such as 22.x where version=3 returns HTTP 500).
          def get_site_info_via_mech_list
            %w[3 2].each do |version|
              opts = {
                'method' => 'GET',
                'uri' => normalize_uri(target_uri.path, 'get_mech_list'),
                'vars_get' => { 'version' => version }
              }
              opts['headers'] = { 'Accept' => 'application/json' } if version == '3'

              res = send_request_cgi(opts)
              next unless res&.code == 200

              company = version == '3' ? parse_mech_list_json(res) : parse_mech_list_text(res)
              next if company.blank?

              vprint_status("Got site info via the /get_mech_list?version=#{version} endpoint.")
              return { company: company, server: nil }
            end

            error('get_site_info_via_mech_list company not found.')
          end

          def parse_mech_list_json(res)
            res.get_json_document['company']
          end

          # Parses semicolon-separated key=value pairs (e.g. "company=sewtest;product=ingredi").
          def parse_mech_list_text(res)
            res.body.split(';').each do |part|
              part.strip!
              return part.sub('company=', '') if part.start_with?('company=')
            end
            nil
          end

          def get_site_info_via_download_client_connector
            res1 = send_request_cgi(
              'method' => 'GET',
              'uri' => normalize_uri(target_uri.path, 'download_client_connector'),
              'vars_get' => {
                'issue_menu' => '1'
              }
            )

            return module_error('get_site_info Connection 1 failed.') unless res1

            return module_error("get_site_info Request 1, unexpected response code #{res1.code}.") unless res1.code == 200

            return module_error('get_site_info_via_download_client_connector Request 1, unable to match data-html-url') unless res1.body =~ %r{data-html-url="\S+(/chat/html/\S+)"}i

            res2 = send_request_cgi(
              'method' => 'GET',
              'uri' => normalize_uri(target_uri.path, Rex::Text.html_decode(::Regexp.last_match(1)))
            )

            return module_error('get_site_info_via_download_client_connector Connection 2 failed.') unless res2

            return module_error("get_site_info_via_download_client_connector Request 2, unexpected response code #{res2.code}.") unless res2.code == 200

            return module_error('get_site_info_via_download_client_connector Request 2, unable to match data-company.') unless res2.body =~ /data-company="(\S+)"/i

            company = Rex::Text.html_decode(::Regexp.last_match(1))

            return module_error('get_site_info_via_download_client_connector Request 2, unable to match data-servers.') unless res2.body =~ /data-servers="(\S+)"/i

            servers = Rex::Text.html_decode(::Regexp.last_match(1))

            servers_array = JSON.parse(servers)

            return module_error('get_site_info_via_download_client_connector Request 2, data-servers not a valid array.') unless servers_array.instance_of? Array

            return module_error('get_site_info_via_download_client_connector Request 2, data-servers is an empty array.') if servers_array.empty?

            server = servers_array.first

            vprint_status('Got site info via the /download_client_connector endpoint.')

            { company: company, server: server }
          rescue JSON::ParserError
            module_error('get_site_info_via_download_client_connector JSON parse error.')
          end

          # Helper method to print an error and then return nil.
          def module_error(message)
            print_error(message)
            nil
          end
        end
      end
    end
  end
end
