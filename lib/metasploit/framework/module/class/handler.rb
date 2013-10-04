# Finds first `Class#ancestor` that can supply #handler_module and uses it.
module Metasploit::Framework::Module::Class::Handler
  # Find {Metasploit::Framework::Module::Ancestor::Handler#handler_module} in `Class#ancestors`.
  #
  # @return [nil] if no ancestor responds to
  #   {Metasploit::Framework::Module::Ancestor::Handler#handler_module #handler_module}.
  # @return [Module] if an ancestor responds to
  #   {Metasploit::Framework::Module::Ancestor::Handler#handler_module #handler_module}.
  def ancestor_handler_module
    unless instance_variable_defined? :@handler_module
      @ancestor_handler_module = nil

      # have to drop first ancestor since it is this class and this method.
      ancestors.each do |ancestor|
        if ancestor.respond_to? :handler_module
          @ancestor_handler_module = ancestor.handler_module
          break
        end
      end
    end

    @ancestor_handler_module
  end
end