# -*- coding: binary -*-

require 'rex/post/meterpreter/object_aliases'
require 'rex/post/meterpreter/extension'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/command_ids'
require 'rex/post/meterpreter/extensions/stdapi/fs/dir'
require 'rex/post/meterpreter/extensions/stdapi/fs/file'
require 'rex/post/meterpreter/extensions/stdapi/fs/file_stat'
require 'rex/post/meterpreter/extensions/stdapi/fs/mount'

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Stdapi_Fs
          module Fs
            include Rex::Post::Meterpreter::Extensions::Stdapi::Fs
          end
          include Rex::Post::Meterpreter::Extensions::Stdapi

          class Stdapi_Fs < Extension

            def self.extension_id
              Rex::Post::Meterpreter::Extensions::Stdapi::EXTENSION_ID_STDAPI
            end

            #
            # Initializes an instance of the Standard API (Fs Namespace) extension.
            #
            def initialize(client)
              super(client, 'stdapi_fs')

              # Alias the following things on the client object so that they
              # can be directly referenced
              client.register_extension_aliases(
                [
                  {
                    'name' => 'fs',
                    'ext'  => ObjectAliases.new(
                      {
                        'dir'      => self.dir,
                        'file'     => self.file,
                        'filestat' => self.filestat,
                        'mount'    => Fs::Mount.new(client)
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
            # Returns a copy of the Dir class.
            #
            def dir
              brand(Rex::Post::Meterpreter::Extensions::Stdapi_Fs::Fs::Dir)
            end

            #
            # Returns a copy of the File class.
            #
            def file
              brand(Rex::Post::Meterpreter::Extensions::Stdapi_Fs::Fs::File)
            end

            #
            # Returns a copy of the FileStat class.
            #
            def filestat
              brand(Rex::Post::Meterpreter::Extensions::Stdapi_Fs::Fs::FileStat)
            end
          end
        end
      end
    end
  end
end