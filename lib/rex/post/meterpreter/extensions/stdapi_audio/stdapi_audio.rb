# -*- coding: binary -*-

require 'rex/post/meterpreter/object_aliases'
require 'rex/post/meterpreter/extension'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/command_ids'
require 'rex/post/meterpreter/extensions/stdapi/mic/mic'
require 'rex/post/meterpreter/extensions/stdapi/audio_output/audio_output'

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Stdapi_Audio
          module AudioOutput
            include Rex::Post::Meterpreter::Extensions::Stdapi::AudioOutput
          end
          module Mic
            include Rex::Post::Meterpreter::Extensions::Stdapi::Mic
          end
          include Rex::Post::Meterpreter::Extensions::Stdapi

          class Stdapi_Audio < Extension

            def self.extension_id
              Rex::Post::Meterpreter::Extensions::Stdapi::EXTENSION_ID_STDAPI
            end

            #
            # Initializes an instance of the Standard API (Audio Namespace) extension.
            #
            def initialize(client)
              super(client, 'stdapi_audio')

              # Alias the following things on the client object so that they
              # can be directly referenced
              client.register_extension_aliases(
                [
                  {
                    'name' => 'audio_output',
                    'ext'  => Rex::Post::Meterpreter::Extensions::Stdapi_Audio::AudioOutput::AudioOutput.new(client)
                  },
                  {
                    'name' => 'mic',
                    'ext'  => Rex::Post::Meterpreter::Extensions::Stdapi_Audio::Mic::Mic.new(client)
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
          end
        end
      end
    end
  end
end