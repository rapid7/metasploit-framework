if (({}.default_proc = nil) rescue true)
  require 'backports/tools/alias_method_chain'
  require 'backports/1.9.1/hash/default_proc'

  class Hash
    def default_proc_with_nil=(proc)
      if proc == nil
        self.default = nil
        self
      else
        self.default_proc_without_nil=(proc)
      end
    end
    Backports.alias_method_chain(self, :default_proc=, :nil)
  end
end
