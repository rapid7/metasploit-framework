unless Module.method_defined? :module_exec
  require 'backports/tools/alias_method'
  require 'backports/1.8.7/kernel/instance_exec'

  class Module
    def module_exec(*arg, &block)
      instance_exec(*arg, &block)
    end
  end
  Backports.alias_method Module, :class_exec, :module_exec
end
