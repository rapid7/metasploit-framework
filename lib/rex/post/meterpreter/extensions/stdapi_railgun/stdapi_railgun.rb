# -*- coding: binary -*-

require 'rex/post/meterpreter/object_aliases'
require 'rex/post/meterpreter/extension'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/command_ids'
require 'rex/post/meterpreter/extensions/stdapi/railgun/railgun'

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Stdapi_Railgun
          module Railgun
            include Rex::Post::Meterpreter::Extensions::Stdapi::Railgun
          end
          include Rex::Post::Meterpreter::Extensions::Stdapi

          class Stdapi_Railgun < Extension

            def self.extension_id
              Rex::Post::Meterpreter::Extensions::Stdapi::EXTENSION_ID_STDAPI
            end

            #
            # Initializes an instance of the Standard API (Railgun Namespace) extension.
            #
            def initialize(client)
              super(client, 'stdapi_railgun')

              # Alias the following things on the client object so that they
              # can be directly referenced
              client.register_extension_aliases(
                [
                    {
                    'name' => 'railgun',
                    'ext'  => Rex::Post::Meterpreter::Extensions::Stdapi_Railgun::Railgun::Railgun.new(client)
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