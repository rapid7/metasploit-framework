# This is borrowed (slightly modified) from Scott Taylor's
# project_path project:
#   http://github.com/smtlaissezfaire/project_path
module RSpec
  module Core
    # @private
    module RubyProject
      def add_to_load_path(*dirs)
        dirs.each { |dir| add_dir_to_load_path(File.join(root, dir)) }
      end

      def add_dir_to_load_path(dir)
        $LOAD_PATH.unshift(dir) unless $LOAD_PATH.include?(dir)
      end

      def root
        @project_root ||= determine_root
      end

      def determine_root
        find_first_parent_containing('spec') || '.'
      end

      def find_first_parent_containing(dir)
        ascend_until { |path| File.exist?(File.join(path, dir)) }
      end

      def ascend_until
        fs = File::SEPARATOR
        escaped_slash = "\\#{fs}"
        special = "_RSPEC_ESCAPED_SLASH_"
        project_path = File.expand_path(".")
        parts = project_path.gsub(escaped_slash, special).squeeze(fs).split(fs).map do |x|
          x.gsub(special, escaped_slash)
        end

        until parts.empty?
          path = parts.join(fs)
          path = fs if path == ""
          return path if yield(path)
          parts.pop
        end
      end

      module_function :add_to_load_path
      module_function :add_dir_to_load_path
      module_function :root
      module_function :determine_root
      module_function :find_first_parent_containing
      module_function :ascend_until
    end
  end
end
