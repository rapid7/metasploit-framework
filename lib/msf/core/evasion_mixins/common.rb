module Msf
  module EvasionMixins
    module Common

      SHELL_TO_SHELL = 'SHELLCODE_TO_SHELLCODE_EVASION_MODULE'.freeze
      SHELL_TO_BIN = 'SHELLCODE_TO_BINARY_EVASION_MODULE'.freeze

      def evasion_enabled?
        @evasion_enabled ||= ::Msf::FeatureManager.instance.enabled?(Msf::FeatureManager::EVASION_MODULE_WORKFLOW)
      end

      def check_child_module_validity(child_module, input_reqs, output_reqs, exe_type)
        result = { valid: true, errors: [] }
        info = child_module.module_info

        if info['ModuleInputs'] != input_reqs
          result[:valid] = false
          result[:errors] << :input_mismatch
        end

        if info['ModuleOutputs'] != output_reqs
          result[:valid] = false
          result[:errors] << :output_mismatch
        end

        # exe type check can be optional
        if exe_type && !info['OutputExecutableTypes']&.include?(exe_type)
          result[:valid] = false
          result[:errors] << :executable_mismatch
        end

        result
      end

      # Configure the provided module with the input and output values.
      # As we won't be interacting with the child module through the UI console, we can set the input to nil.
      # This does _not_ affect our ability to have a Pry breakpoint in the module, so it's okay to set it to nil.
      def configure_module_io(mod, mod_input, mod_output)
        # self.user_input example:
        # => #<Rex::Ui::Text::Input::Readline:0x00000001336d66c0
        # @output=#<Rex::Ui::Text::Output::Stdio:0x0000000133e9a2d0 @at_prompt=false, @config={:color=>:auto}, @input=nil, @io=#<IO:<STDOUT>>>,
        # @prompt="\x01\e[4m\x02msf\x01\e[0m\x02 exploit(\x01\e[1m\x02\x01\e[31m\x02windows/smb/psexec\x01\e[0m\x02) \x01\e[0m\x02> ",
        # @rl_saved_proc=#<Proc:0x00000001336d5fb8 /Users/sjanusz/Programming/metasploit-framework/lib/rex/ui/text/input/readline.rb:194>>
        # This means we might need to change the prompt?
        # Or at least:
        # mod.user_input = Rex::Ui::Text::Input::Readline.new
        # mod.user_input.output = self.user_input.output
        # We can likely ignore the rl_saved_proc; we won't be interacting with the module itself
        # For output:
        # => #<Rex::Ui::Text::Output::Stdio:0x0000000133e9a2d0 @at_prompt=false, @config={:color=>:auto}, @input=nil, @io=#<IO:<STDOUT>>>
        # We should be able to do:
        # mod.user_output = self.user_output

        mod.init_ui(mod_input, mod_output)
      end

      def module_workflow(datastore_opt, opts: {})
        mod = create_child_module(self.framework, datastore_opt)
        return nil unless mod

        configure_module(mod, opts: opts)
        mod.run
      end

      def shellcode_to_shellcode_evasion_set?
        !datastore[SHELL_TO_SHELL].blank?
      end

      def shellcode_to_binary_evasion_set?
        !datastore[SHELL_TO_BIN].blank?
      end

      def perform_x_to_y_evasion(datastore_opt, input, opts: {})
        if datastore[datastore_opt].blank?
          vprint_status("#{datastore_opt} datastore option not set. Ignoring, and not performing this type of evasion.")
          return input
        end

        # Create, configure and run the x->y evasion module
        module_workflow(datastore[datastore_opt], opts: opts)
      end

      def perform_shellcode_to_shellcode_evasion(input, opts: {})
        perform_x_to_y_evasion(SHELL_TO_SHELL, input, opts: opts) || input
      end

      def perform_shellcode_to_binary_evasion(input, opts: {})
        perform_x_to_y_evasion(SHELL_TO_BIN, input, opts: opts) || input
      end

      # TODO: Modify this.
      def configure_module_payload(mod, opts: {})
        # Process shellcode-to-shellcode here maybe?
        correct_payload = opts[:custom_payload] || self.payload&.deep_dup || MockPayload.new(opts: opts)

        generate_single_payload_proc = ->(_pinst = nil, _platform = nil, _arch = nil, _explicit_target = nil) { correct_payload }
        mod.define_singleton_method(:generate_single_payload, &generate_single_payload_proc)

        payload_proc = -> { correct_payload }
        mod.define_singleton_method(:payload, &payload_proc)
      end

      def configure_module_target(mod, opts: {})
        correct_target = if self.respond_to?(:target)
          # TODO: Should we priorities opts[:arch] here instead of self.target.arch?
          self.target
        else # This is tricky. In the scenario of a cmd staged payload, we don't have a 'target' here.
          correct_arch = opts[:arch] || self.stage_arch
          target_opts = opts.merge({ 'Arch' => correct_arch })
          ::Msf::Exploit::Target.new('MockTarget', target_opts)
        end

        target_proc = -> { correct_target }
        mod.define_singleton_method(:target, &target_proc)
      end

      def configure_module_datastore(mod)
        # Configure some known options that Pro also configures:
        %w[VERBOSE AutoRunScript WORKSPACE].each { |opt_name| mod.datastore[opt_name] = self.datastore[opt_name].dup }
        # https://github.com/rapid7/pro/commit/1a05bc8fb1d9bfc2d9ca00484b44bc0344ec9a60
        # Commit by HDM in Pro from 16 years ago; let's keep it around, no idea what the scenario is though, how it works or even _if_ it does
        # Force any TCP listeners to use the local communication channel only
        mod.datastore['ListenerComm'] = 'local'
        # For compatibility with Pro, we might need to set the mod[:task] here as well.
        mod[:task] = self[:task]
      end

      def configure_module(mod, opts: {})
        mod.import_defaults
        mod.register_parent(self)

        configure_module_datastore(mod)
        configure_module_io(mod, nil, self.user_output)
        configure_module_payload(mod, opts: opts)
        configure_module_target(mod, opts: opts)
      end

      def create_child_module(framework, module_name)
        raise ArgumentError, "Provided Framework object is nil" if framework.nil?
        raise ArgumentError, "Provided module name is nil" if module_name.nil?

        module_instance = framework.modules.create(module_name)
        raise "Something went wrong when creating the requested evasion module: '#{module_name}'" if module_instance.nil?

        module_instance
      end

      # In scenarios where we don't have a payload at the top-level.
      # This will occur in scenarios where we have a CMD fetch payload.
      class MockPayload
        attr_accessor :encoded, :arch

        def initialize(opts: {})
          @encoded = opts[:code].dup
          @arch = opts[:arch].dup
        end
      end
    end
  end
end