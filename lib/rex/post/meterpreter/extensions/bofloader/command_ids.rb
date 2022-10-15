# -*- coding: binary -*-

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Bofloader
          # ID for the extension (needs to be a multiple of 1000)
          EXTENSION_ID_BOFLOADER = 18000

          # Associated command ids
          COMMAND_ID_BOFLOADER_EXECUTE = EXTENSION_ID_BOFLOADER + 1
        end
      end
    end
  end
end
