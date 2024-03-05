module Acceptance
  ###
  # Stores the data for a target. These credentials can be used to create a sesion, or run a module against
  ###
  class Target
    attr_reader :session_module, :type, :datastore

    def initialize(options)
      @type = options.fetch(:type)
      @session_module = options.fetch(:session_module)
      @datastore = options.fetch(:datastore)
    end

    def [](k)
      options[k]
    end

    # @param [Hash] default_global_datastore
    # @return [String] The setg commands for setting the global datastore
    def setg_commands(default_global_datastore: {})
      commands = []
      # Ensure the global framework datastore is always clear
      commands << "irb -e '(self.respond_to?(:framework) ? framework : self).datastore.user_defined.clear'"
      # Call setg
      global_datastore = default_global_datastore.merge(@datastore[:global])
      global_datastore.each do |key, value|
        commands << "setg #{key} #{value}"
      end
      commands.join("\n")
    end

    # @param [Hash] default_module_datastore
    # @return [String] The datastore options string
    def datastore_options(default_module_datastore: {})
      module_datastore = default_module_datastore.merge(@datastore[:module])
      module_options = module_datastore.map do |key, value|
        "#{key}=#{value}"
      end

      module_options.join(' ')
    end

    # @param [Hash] default_module_datastore
    # @return [String] The command which can be used on msfconsole to generate the payload
    def run_command(default_module_datastore: {})
      "run #{datastore_options(default_module_datastore: default_module_datastore)}"
    end

    # @param [Hash] default_global_datastore
    # @param [Hash] default_module_datastore
    # @return [String] A human readable representation of the payload configuration object
    def as_readable_text(default_global_datastore: {}, default_module_datastore: {})
      <<~EOF
         ## Session module 
         use #{session_module}

         ## Set global datastore
         #{setg_commands(default_global_datastore: default_global_datastore)}

         ## Run command
         #{run_command(default_module_datastore: default_module_datastore)}
      EOF
    end
  end
end
