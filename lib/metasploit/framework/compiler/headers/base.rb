module Metasploit
  module Framework
    module Compiler
      module Headers
        class Base

          attr_accessor :loaded_dep

          # Initializes the Base class for headers.
          def initialize
            # This is used to avoid loading the same dependency code twice
            @loaded_dep = []
          end

          # Returns the header source code.
          #
          # @param lib_name [String] The file name of the header.
          # @return [String]
          def include(lib_name)
            lib = lib_dep_map[lib_name]
            unless lib
              raise RuntimeError, "#{lib_name} not found"
            end

            # Load the dependencies first, and only once
            dep = ''
            lib.each do |f|
              unless loaded_dep.include?(f)
                dep_path = File.join(headers_path, f)
                dep << File.read(dep_path) << "\n"
                loaded_dep << f
              end
            end

            # Load the headers
            lib_path = File.join(headers_path, lib_name)
            "#{dep}#{File.read(lib_path)}"
          end

        end
      end
    end
  end
end