unless Method.method_defined? :super_method
  require 'backports/1.8.7/array/find_index'

  class Method
    def super_method
      singleton_klass = class << receiver; self; end
      call_chain = singleton_klass.ancestors
      # find current position in call chain:
      skip = call_chain.find_index{|c| c == owner} or return
      call_chain = call_chain.drop(skip + 1)
      # find next in chain with a definition:
      next_index = call_chain.find_index{|c| c.method_defined? name}
      next_index && call_chain[next_index].instance_method(name).bind(receiver)
    end
  end
end
