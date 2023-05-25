# -*- coding: binary -*-

module Msf
  class Post
    module Windows
      module Eventlog
        include Msf::Post::Windows::Version

        def initialize(info = {})
          super(
            update_info(
              info,
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_sys_eventlog_*
                  ]
                }
              }
            )
          )
        end

        #
        # Enumerate eventlogs
        #
        def eventlog_list
          key = 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\'
          version = get_version_info
          if version.build_number.between?(Msf::WindowsVersion::Win2000, Msf::WindowsVersion::Server2003_SP2)
            key = "#{key}Eventlog"
          else
            key = "#{key}eventlog"
          end
          eventlogs = registry_enumkeys(key)
          return eventlogs
        end

        #
        # Clears a given eventlog or all eventlogs if none is given. Returns an array of eventlogs
        # that where cleared.
        #
        def eventlog_clear(evt = '')
          evntlog = []
          if evt.empty?
            evntlog = eventloglist
          else
            evntlog << evt
          end
          evntlog.each do |e|
            log = session.sys.eventlog.open(e)
            log.clear
          end
          return evntlog
        end
      end
    end
  end
end
