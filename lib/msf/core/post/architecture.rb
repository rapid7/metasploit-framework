# -*- coding: binary -*-

module Msf::Post::Architecture

  # Get the architecture of the target's operating system.
  # @return [String, Nil] Returns a string containing the target OS architecture if known, or Nil if its not known.
  #
  def get_os_architecture
    if session.type == 'meterpreter'
      os_architecture = sysinfo['Architecture']
      if session.platform == 'linux'
        if %w[ armv5l armv6l armv7l ].include?(os_architecture)
          os_architecture = ARCH_ARMLE
        end
      end
      return os_architecture
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
      when 'linux', 'bsd', 'osx'
        uname_m = cmd_exec('uname -m').to_s.strip
        Rex::Arch.from_uname(uname_m)
      end
    end
  end
end
