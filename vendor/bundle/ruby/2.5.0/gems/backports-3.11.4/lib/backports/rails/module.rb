class Module
  # Standard in rails... See official documentation[http://api.rubyonrails.org/classes/ActiveSupport/CoreExtensions/Module.html]
  def alias_method_chain(target, feature, &block)
    Backports.alias_method_chain(self, target, feature, &block)
  end unless method_defined? :alias_method_chain
end
