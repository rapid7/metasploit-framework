RSpec::Support.require_rspec_support 'ruby_features'

module RSpec
  module Support
    # @api private
    #
    # Replacement for fileutils#mkdir_p because we don't want to require parts
    # of stdlib in RSpec.
    class DirectoryMaker
      # @api private
      #
      # Implements nested directory construction
      def self.mkdir_p(path)
        stack = generate_stack(path)
        path.split(File::SEPARATOR).each do |part|
          stack = generate_path(stack, part)
          begin
            Dir.mkdir(stack) unless directory_exists?(stack)
          rescue Errno::EEXIST => e
            raise e unless directory_exists?(stack)
          rescue Errno::ENOTDIR => e
            raise Errno::EEXIST, e.message
          end
        end
      end

      if OS.windows_file_path?
        def self.generate_stack(path)
          if path.start_with?(File::SEPARATOR)
            File::SEPARATOR
          elsif path[1] == ':'
            ''
          else
            '.'
          end
        end
        def self.generate_path(stack, part)
          if stack == ''
            part
          elsif stack == File::SEPARATOR
            File.join('', part)
          else
            File.join(stack, part)
          end
        end
      else
        def self.generate_stack(path)
          path.start_with?(File::SEPARATOR) ? File::SEPARATOR : "."
        end
        def self.generate_path(stack, part)
          File.join(stack, part)
        end
      end

      def self.directory_exists?(dirname)
        File.exist?(dirname) && File.directory?(dirname)
      end
      private_class_method :directory_exists?
      private_class_method :generate_stack
      private_class_method :generate_path
    end
  end
end
