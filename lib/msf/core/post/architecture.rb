# -*- coding: binary -*-

module Msf::Post::Architecture

  def initialize(info = {})
    super(
      update_info(
        info,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
            ]
          }
        }
      )
    )
  end

  # Get the architecture of the target's operating system.
  # @return [String, Nil] Returns a string containing the target OS architecture if known, or Nil if its not known.
  def get_os_architecture
    if session.type == 'meterpreter'
      return sysinfo['Architecture']
    else
      case session.platform
      when 'windows', 'win'
        # Check for 32-bit process on 64-bit arch
        arch = get_env('PROCESSOR_ARCHITEW6432')
        if arch.strip.empty? or arch =~ /PROCESSOR_ARCHITEW6432/
          arch = get_env('PROCESSOR_ARCHITECTURE')
        end
        if arch =~ /AMD64/m
          return ARCH_X64
        elsif arch =~ /86/m
          return ARCH_X86
        elsif arch =~ /ARM64/m
          return ARCH_AARCH64
        else
          print_error('Target is running Windows on an unsupported architecture!')
          return nil
        end
      end
    end
  end
end