unless Method.method_defined? :name
  require 'backports/tools/alias_method_chain'

  class Method
    attr_accessor :name, :receiver, :owner

    def unbind_with_additional_info
      unbound = unbind_without_additional_info
      unbound.name = name
      unbound.owner = owner
      unbound
    end
    Backports.alias_method_chain self, :unbind, :additional_info
  end

  class UnboundMethod
    attr_accessor :name, :owner

    def bind_with_additional_info(to)
      bound = bind_without_additional_info(to)
      bound.name = name
      bound.owner = owner
      bound.receiver = to
      bound
    end
    Backports.alias_method_chain self, :bind, :additional_info
  end

  module Kernel
    def method_with_additional_info(name)
      bound = method_without_additional_info(name)
      bound.name = name.to_s
      bound.receiver = self
      bound.owner = self.class.ancestors.find{|mod| mod.instance_methods(false).include? bound.name}
      bound
    end
    Backports.alias_method_chain self, :method, :additional_info
  end

  class Module
    def instance_method_with_additional_info(name)
      unbound = instance_method_without_additional_info(name)
      unbound.name = name.to_s
      unbound.owner = ancestors.find{|mod| mod.instance_methods(false).include? unbound.name}
      unbound
    end
    Backports.alias_method_chain self, :instance_method, :additional_info
  end
end
