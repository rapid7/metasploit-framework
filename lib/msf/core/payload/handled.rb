ActiveSupport::Concern

module Msf::Payload::Handled
  extend ActiveSupport::Concern

  module ClassMethods
    # Sets the {#handler_module} and {#handler_type_alias} for handled payloads.  Handled payloads are singles or
    # stagers.
    #
    # @param options [Hash{Symbol => String}]
    # @option options [String] :module_name `Module#name` of handler `Module`.
    # @option options [String] :type_alias type suffix to use in `Metasploit::Model::Module::Class#reference_name`
    #   in place of {#handler_module handler Module's} `#handler_type`.
    # @return [void]
    # @raise [KeyError] if `:module_name` is not given
    def handler(options={})
      options.assert_valid_keys(:module_name, :type_alias)
      @handler_module_name = options.fetch(:module_name)
      @handler_type_alias = options[:type_alias]
    end

    # `Module` with `Module#name` of {#handler_module_name}.
    #
    # @return [Module]
    def handler_module
      @handler_module ||= handler_module_name.constantize
    end

    # `Module#name` passed to {#handler}'s `:module_type` option.
    #
    # @return [String] string passed to :module_type
    # @return ['Msf::Handler::None'] if {#handler} was not called.
    def handler_module_name
      @handler_module_name ||= 'Msf::Handler::None'
    end

    # Type to use as suffix in `Metasploit::Model::Module::Class#refernce_name`.
    #
    # @return [String] `:type_alias` passed to {#handler}.
    # @return [String] {#handler_module handler Module's} `#handler_type` if `:type_alias` not passed to {#handler}
    def handler_type_alias
      @handler_type_alias ||= handler_module.handler_type
    end
  end
end