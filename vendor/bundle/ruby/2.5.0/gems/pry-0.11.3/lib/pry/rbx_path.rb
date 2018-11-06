class Pry
  module RbxPath
    module_function
    def is_core_path?(path)
      Pry::Helpers::BaseHelpers.rbx? && (path.start_with?("kernel") || path.start_with?("lib")) && File.exist?(convert_path_to_full(path))
    end

    def convert_path_to_full(path)
      if path.start_with?("kernel")
        File.join File.dirname(Rubinius::KERNEL_PATH), path
      elsif path.start_with?("lib")
        File.join File.dirname(Rubinius::LIB_PATH), path
      else
        path
      end
    end

    def rvm_ruby?(path)
      !!(path =~ /\.rvm/)
    end
  end
end
