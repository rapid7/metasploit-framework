unless Kernel.private_method_defined? :require_relative
  require 'backports/tools/path'

  module Kernel
    def require_relative(relative_feature)
      file = caller.first.split(/:\d/,2).first
      if /\A\((.*)\)/ =~ file # eval, etc.
        raise LoadError, "require_relative is called in #{$1}"
      end
      require File.expand_path(Backports.convert_path(relative_feature), File.dirname(file))
    end
    private :require_relative
  end
end
