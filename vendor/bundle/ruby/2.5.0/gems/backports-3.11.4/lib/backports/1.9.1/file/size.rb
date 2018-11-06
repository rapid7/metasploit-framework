unless File.method_defined? :size
  class File
    def size
      stat.size
    end
  end
end

if RUBY_VERSION < '1.9'
  require 'backports/tools/path'

  Backports.convert_first_argument_to_path File, :size?
  Backports.convert_first_argument_to_path File, :size
end
