# -*- coding: binary -*-

module Msf
  class Post
    module Windows
      module System
        include Msf::Post::Common

        def initialize(info = {})
          super(
            update_info(
              info,
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_sys_config_sysinfo
                  ]
                }
              }
            )
          )
        end

        #
        # Gets the hostname of the system
        #
        # @return [String] hostname
        #
        def get_hostname
          hostname = nil

          if session.type == 'meterpreter'
            hostname = session.sys.config.sysinfo['Computer'].to_s
          end

          if hostname.blank? && session.type == 'powershell'
            hostname = cmd_exec('[System.Net.Dns]::GetHostName()').to_s
          end

          if hostname.blank? && command_exists?('hostname')
            hostname = cmd_exec('hostname').to_s
          end

          if hostname.blank?
            hostname = get_env('COMPUTERNAME').to_s
          end

          raise if hostname.blank?

          report_host({ host: rhost, name: hostname.downcase })
          hostname.downcase
        rescue StandardError
          raise 'Unable to retrieve hostname'
        end
      end
    end
  end
end
