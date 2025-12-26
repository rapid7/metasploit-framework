# -*- coding: binary -*-
require 'rex/post/meterpreter/object_aliases'
require 'rex/post/meterpreter/extension'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/command_ids'
require 'rex/post/meterpreter/extensions/stdapi/sys/config'
require 'rex/post/meterpreter/extensions/stdapi/sys/process'
require 'rex/post/meterpreter/extensions/stdapi/sys/registry'
require 'rex/post/meterpreter/extensions/stdapi/sys/event_log'
require 'rex/post/meterpreter/extensions/stdapi/sys/power'

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Stdapi_Sys
          module Sys
            include Rex::Post::Meterpreter::Extensions::Stdapi::Sys
          end
          include Rex::Post::Meterpreter::Extensions::Stdapi

          class Stdapi_Sys < Extension

            def self.extension_id
              Rex::Post::Meterpreter::Extensions::Stdapi::EXTENSION_ID_STDAPI
            end

            #
            # Initializes an instance of the Standard API (Sys Namespace) extension.
            #
            def initialize(client)
              super(client, 'stdapi_sys')

              # Alias the following things on the client object so that they
              # can be directly referenced
              client.register_extension_aliases(
                [
                  {
                    'name' => 'sys',
                    'ext'  => ObjectAliases.new(
                      {
                        'config'   => Rex::Post::Meterpreter::Extensions::Stdapi_Sys::Sys::Config.new(client),
                        'process'  => self.process,
                        'registry' => self.registry,
                        'eventlog' => self.eventlog,
                        'power'    => self.power
                      })
                  },
                ])
            end

            #
            # Sets the client instance on a duplicated copy of the supplied class.
            #
            def brand(klass)
              klass = klass.dup
              klass.client = self.client
              return klass
            end

            #
            # Returns a copy of the Process class.
            #
            def process
              brand(Rex::Post::Meterpreter::Extensions::Stdapi_Sys::Sys::Process)
            end

            #
            # Returns a copy of the Registry class.
            #
            def registry
              brand(Rex::Post::Meterpreter::Extensions::Stdapi_Sys::Sys::Registry)
            end

            #
            # Returns a copy of the EventLog class.
            #
            def eventlog
              brand(Rex::Post::Meterpreter::Extensions::Stdapi_Sys::Sys::EventLog)
            end

            #
            # Returns a copy of the Power class.
            #
            def power
              brand(Rex::Post::Meterpreter::Extensions::Stdapi_Sys::Sys::Power)
            end
          end
        end
      end
    end
  end
end
