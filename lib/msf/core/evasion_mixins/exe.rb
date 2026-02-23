# -*- coding: binary -*-
#
# frozen_string_literal: true

require 'msf/core/evasion_mixins/common'

# A mixin used for providing Modules with payload evasion options and helper methods.
# Prepended onto Msf::Exploit::EXE so that generate_payload_exe and
# generate_payload_exe_service are intercepted when the evasion workflow
# feature flag is enabled.
#
module Msf
  module EvasionMixins
    module EXE

    include Msf::EvasionMixins::Common

    # In the future to support binary -> binary evasion, override: def exe_post_generation(bin, opts)

    # Overrides Msf::Exploit::EXE#generate_payload_exe via prepend.
    def generate_payload_exe(opts = {})
      return super unless evasion_enabled?
      # Return if there are no evasion options set.
      return super unless shellcode_to_shellcode_evasion_set? || shellcode_to_binary_evasion_set?

      print_status("Generating EXE payload...")

      # Step 1: Run shellcode-to-shellcode evasion if configured.
      # This transforms the raw payload shellcode (e.g. encryption, encoding)
      # and returns the modified shellcode.
      transformed_shellcode = nil
      if shellcode_to_shellcode_evasion_set?
        print_status("Running Shellcode-to-Shellcode evasion module: #{datastore[SHELL_TO_SHELL]}...")
        transformed_shellcode = module_workflow(datastore[SHELL_TO_SHELL], opts: opts)

        if transformed_shellcode.nil?
          print_error("Shellcode-to-Shellcode evasion module failed. Continuing without shellcode transformation.")
        end
      end

      # Build a custom payload object carrying the transformed shellcode so
      # that downstream modules (or super) receive it via payload.encoded.
      evasion_opts = opts.dup
      if transformed_shellcode
        evasion_opts[:custom_payload] = MockPayload.new(opts: { code: transformed_shellcode, arch: opts[:arch] || target_arch })
      end

      # Step 2: Run shellcode-to-binary evasion if configured.
      # This takes the (possibly transformed) shellcode and produces a full executable.
      if shellcode_to_binary_evasion_set?
        result = process_payload_and_return_executable(opts: evasion_opts)
        return result if result
      end

      # No shellcode-to-binary module, or it failed — fall back to the
      # standard EXE generation, injecting transformed shellcode via :code.
      evasion_opts[:code] = transformed_shellcode if transformed_shellcode
      super(evasion_opts)
    end

    # Overrides Msf::Exploit::EXE#generate_payload_exe_service via prepend.
    def generate_payload_exe_service(opts = {})
      return super unless evasion_enabled?
      return super unless shellcode_to_shellcode_evasion_set? || shellcode_to_binary_evasion_set?

      print_status("Generating EXE Service payload...")

      # Step 1: Shellcode-to-shellcode evasion.
      transformed_shellcode = nil
      if shellcode_to_shellcode_evasion_set?
        print_status("Running Shellcode-to-Shellcode evasion module: #{datastore[SHELL_TO_SHELL]}...")
        transformed_shellcode = module_workflow(datastore[SHELL_TO_SHELL], opts: opts)

        if transformed_shellcode.nil?
          print_error("Shellcode-to-Shellcode evasion module failed. Continuing without shellcode transformation.")
        end
      end

      evasion_opts = opts.dup
      if transformed_shellcode
        evasion_opts[:custom_payload] = MockPayload.new(opts: { code: transformed_shellcode, arch: opts[:arch] || target_arch })
      end

      # Step 2: Shellcode-to-binary evasion.
      if shellcode_to_binary_evasion_set?
        result = process_payload_and_return_executable_service(opts: evasion_opts)
        return result if result
      end

      evasion_opts[:code] = transformed_shellcode if transformed_shellcode
      super(evasion_opts)
    end

    private

    def process_payload_and_return_executable(opts: {})
      module_instance = create_child_module(self.framework, datastore[SHELL_TO_BIN])

      validity_result = check_child_module_validity(module_instance, 'Payload', 'Executable', nil)
      vprint_error "The selected Shellcode-to-Binary evasion module is not suitable for the current payload" unless validity_result[:valid]
      return nil unless validity_result[:valid]

      configure_module(module_instance, opts: opts)
      print_status("Running Shellcode-to-Binary evasion module: #{datastore[SHELL_TO_BIN]}...")
      module_instance.run
    end

    def process_payload_and_return_executable_service(opts: {})
      process_payload_and_return_executable(opts: opts)
    end
  end
end
end
