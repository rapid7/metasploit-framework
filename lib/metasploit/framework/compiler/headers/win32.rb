
require 'metasploit/framework/compiler/headers/base'

module Metasploit
  module Framework
    module Compiler
      module Headers
        class Win32 < Base

          attr_accessor :lib_dep_map
          attr_accessor :headers_path

          # Initializes the Win32 headers.
          def initialize
            super
            @headers_path = File.join(Msf::Config.install_root, 'data', 'headers', 'win32')
            @lib_dep_map = {
              'stddef.h'   => [],
              'Windows.h'  => ['stddef.h']
            }
          end

        end
      end
    end
  end
end

