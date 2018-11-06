unless Hash.method_defined? :default_proc=
  require 'backports/tools/arguments'

  class Hash
    def default_proc=(proc)
      if proc == nil # nil accepted in Ruby 2.0
        self.default = nil
        self
      else
        replace(Hash.new(&Backports.coerce_to(proc, Proc, :to_proc)).merge!(self))
      end
    end
  end
end
