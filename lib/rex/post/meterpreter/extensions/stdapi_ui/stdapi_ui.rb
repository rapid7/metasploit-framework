# -*- coding: binary -*-

require 'rex/post/meterpreter/object_aliases'
require 'rex/post/meterpreter/extension'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/command_ids'
require 'rex/post/meterpreter/extensions/stdapi/mic/mic'
require 'rex/post/meterpreter/extensions/stdapi/audio_output/audio_output'
require 'rex/post/meterpreter/extensions/stdapi/webcam/webcam'
require 'rex/post/meterpreter/extensions/stdapi/sys/config'
require 'rex/post/meterpreter/extensions/stdapi/sys/process'
require 'rex/post/meterpreter/extensions/stdapi/sys/registry'
require 'rex/post/meterpreter/extensions/stdapi/sys/event_log'
require 'rex/post/meterpreter/extensions/stdapi/sys/power'
require 'rex/post/meterpreter/extensions/stdapi/ui'

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Stdapi_Ui
          module AudioOutput
            include Rex::Post::Meterpreter::Extensions::Stdapi::AudioOutput
          end

          module Mic
            include Rex::Post::Meterpreter::Extensions::Stdapi::Mic
          end

          module Webcam
            include Rex::Post::Meterpreter::Extensions::Stdapi::Webcam
          end

          module Sys
            include Rex::Post::Meterpreter::Extensions::Stdapi::Sys
          end
          include Rex::Post::Meterpreter::Extensions::Stdapi

          class Stdapi_Ui < Extension

            def self.extension_id
              Rex::Post::Meterpreter::Extensions::Stdapi::EXTENSION_ID_STDAPI
            end

            #
            # Initializes an instance of the Standard API (Ui Namespace) extension.
            #
            def initialize(client)
              super(client, 'stdapi_ui')

              # Alias the following things on the client object so that they
              # can be directly referenced
              client.register_extension_aliases(
                [
                  {
                    'name' => 'audio_output',
                    'ext' => Rex::Post::Meterpreter::Extensions::Stdapi_Ui::AudioOutput::AudioOutput.new(client)
                  },
                  {
                    'name' => 'mic',
                    'ext' => Rex::Post::Meterpreter::Extensions::Stdapi_Ui::Mic::Mic.new(client)
                  },
                  {
                    'name' => 'sys',
                    'ext' => ObjectAliases.new(
                      {
                        'config' => Rex::Post::Meterpreter::Extensions::Stdapi_Ui::Sys::Config.new(client),
                        'process' => process,
                        'registry' => registry,
                        'eventlog' => eventlog,
                        'power' => power
                      }
                    )
                  },
                  {
                    'name' => 'ui',
                    'ext' => Rex::Post::Meterpreter::Extensions::Stdapi::UI.new(client)
                  },
                  {
                    'name' => 'webcam',
                    'ext' => Rex::Post::Meterpreter::Extensions::Stdapi_Ui::Webcam::Webcam.new(client)
                  },
                ]
              )
            end

            #
            # Sets the client instance on a duplicated copy of the supplied class.
            #
            def brand(klass)
              klass = klass.dup
              klass.client = client
              return klass
            end

            #
            # Returns a copy of the Process class.
            #
            def process
              brand(Rex::Post::Meterpreter::Extensions::Stdapi_Ui::Sys::Process)
            end

            #
            # Returns a copy of the Registry class.
            #
            def registry
              brand(Rex::Post::Meterpreter::Extensions::Stdapi_Ui::Sys::Registry)
            end

            #
            # Returns a copy of the EventLog class.
            #
            def eventlog
              brand(Rex::Post::Meterpreter::Extensions::Stdapi_Ui::Sys::EventLog)
            end

            #
            # Returns a copy of the Power class.
            #
            def power
              brand(Rex::Post::Meterpreter::Extensions::Stdapi_Ui::Sys::Power)
            end
          end
        end
      end
    end
  end
end
