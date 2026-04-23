# -*- coding: binary -*-
#
# frozen_string_literal: true

require 'msf/core/evasion_mixins/common'

# A mixin used for providing Modules with payload evasion options and helper methods.
# Prepended onto Msf::Util::EXE so that executable generation methods are
# intercepted when the evasion workflow feature flag is enabled.
#
module Msf
module EvasionMixins
  module UtilExe

    include Msf::EvasionMixins::Common

    def to_executable(framework, arch, plat, code = '', fmt = '', opts = {})
      return super unless evasion_enabled?

      vprint_status("Creating an executable for: #{plat} - #{arch} ...")
      super
    end

    def to_executable_fmt(framework, arch, plat, code, fmt, exeopts)
      return super unless evasion_enabled?

      # For backwards compatibility with the way this gets called when
      # generating from Msf::Simple::Payload.generate_simple
      if arch.is_a? Array
        output = nil
        arch.each do |a|
          output = to_executable_fmt(framework, a, plat, code, fmt, exeopts)
          break if output
        end
        return output
      end

      vprint_status("Creating an executable for #{platform} - #{arch}")

      #code = shellcode_to_shellcode_evasion_enabled? ? (perform_shellcode_to_shellcode_evasion(code, opts: exeopts) || code) : code
#
      ## If we don't do shellcode->binary, call off to the original method to take care of that for us.
      #return super unless shellcode_to_binary_evasion_enabled?
#
      #perform_shellcode_to_binary_evasion(code, opts: exeopts)
    end

    def to_executable_windows_x64(framework, code, fmt = 'exe', opts = {})
      return super unless evasion_enabled?
      # Our Windows evasion modules create an EXE, not a DLL.
      return super if fmt.include?('dll')

      vprint_status("Creating an executable for Windows - x64")

      #code = shellcode_to_shellcode_evasion_enabled? ? (perform_shellcode_to_shellcode_evasion(code, opts: opts) || code) : code
#
      #return super unless shellcode_to_binary_evasion_enabled?
#
      #perform_shellcode_to_binary_evasion(code, opts: opts)
    end

    def to_executable_windows_x86(framework, code, fmt = 'exe', opts = {})
      return super unless evasion_enabled?
      return super if fmt.include?('dll')

      vprint_status("Creating an executable for Windows - x86")

      #code = shellcode_to_shellcode_evasion_enabled? ? (perform_shellcode_to_shellcode_evasion(code, opts: opts) || code) : code
#
      #return super unless shellcode_to_binary_evasion_enabled?
#
      #perform_shellcode_to_binary_evasion(code, opts: opts)
    end

    def to_exe_elf(framework, opts, template, code, big_endian = false)
      return super unless evasion_enabled?
      
      # Taken from the original method definition.
      if elf? code
        return code
      end

      vprint_status("Creating an executable ELF file...")

      #code = shellcode_to_shellcode_evasion_enabled? ? (perform_shellcode_to_shellcode_evasion(code, opts: opts) || code) : code
#
      ## If we don't do shellcode->binary, call off to the original method to take care of that for us.
      #return super unless shellcode_to_binary_evasion_enabled?
#
      #perform_shellcode_to_binary_evasion(code, opts: opts)
    end
  end
end
end
