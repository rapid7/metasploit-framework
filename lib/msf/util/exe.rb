# -*- coding: binary -*-

module Msf::Util::EXE
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Windows
  include Msf::Util::EXE::Linux
  include Msf::Util::EXE::OSX
  include Msf::Util::EXE::Solaris
  include Msf::Util::EXE::Bsd

  include Msf::Util::EXE::Windows::Common
  include Msf::Util::EXE::Linux::Common
  include Msf::Util::EXE::OSX::Common

  include Msf::Util::EXE::Windows::X86
  include Msf::Util::EXE::Windows::X64
  include Msf::Util::EXE::Windows::Aarch64

  include Msf::Util::EXE::Linux::X86
  include Msf::Util::EXE::Linux::X64
  include Msf::Util::EXE::Linux::Armle
  include Msf::Util::EXE::Linux::Aarch64
  include Msf::Util::EXE::Linux::Mipsle
  include Msf::Util::EXE::Linux::Mipsbe
  include Msf::Util::EXE::Linux::Mips64
  include Msf::Util::EXE::Linux::Riscv32le
  include Msf::Util::EXE::Linux::Riscv64le
  include Msf::Util::EXE::Linux::Ppc
  include Msf::Util::EXE::Linux::Ppc64
  include Msf::Util::EXE::Linux::Ppce500v2
  include Msf::Util::EXE::Linux::Zarch
  include Msf::Util::EXE::Linux::Loongarch64

  include Msf::Util::EXE::OSX::X86
  include Msf::Util::EXE::OSX::X64
  include Msf::Util::EXE::OSX::Armle
  include Msf::Util::EXE::OSX::Aarch64
  include Msf::Util::EXE::OSX::Ppc
  include Msf::Util::EXE::OSX::App

  include Msf::Util::EXE::Solaris::X86

  include Msf::Util::EXE::Bsd::X86
  include Msf::Util::EXE::Bsd::X64

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods

    # to_executable
    #
    # @param framework [Msf::Framework]
    # @param arch     [String]
    # @param plat     [String]
    # @param code     [String]
    # @param fmt      [String]
    # @param opts     [Hash]
    def to_executable(framework, arch, plat, code = '', fmt='', opts = {})
      # This code handles mettle stageless when LinuxMinKernel is 2.4+ because the code will be a elf or macho.
      if elf?(code) || macho?(code)
        return code
      end

      if fmt.empty?
        fmt = 'exe' if plat.index(Msf::Module::Platform::Windows)
        fmt = 'macho' if plat.index(Msf::Module::Platform::OSX)
        fmt = 'elf' if plat.index(Msf::Module::Platform::Linux) || plat.index(Msf::Module::Platform::BSD) || plat.index(Msf::Module::Platform::Solaris)
      end

      return to_executable_linux(framework, arch, code, fmt, opts)    if plat.index(Msf::Module::Platform::Linux)
      return to_executable_osx(framework, arch, code, fmt, opts)      if plat.index(Msf::Module::Platform::OSX)
      return to_executable_solaris(framework, arch, code, fmt, opts)  if plat.index(Msf::Module::Platform::Solaris)
      return to_executable_windows(framework, arch, code, fmt, opts)  if plat.index(Msf::Module::Platform::Windows)
      return to_executable_bsd(framework, arch, code, fmt, opts)      if plat.index(Msf::Module::Platform::BSD)

      nil
    end


    #
    # Generate an executable of a given format suitable for running on the
    # architecture/platform pair.
    #
    # This routine is shared between msfvenom, rpc, and payload modules (use
    # <payload>)
    #
    # @param framework [Framework]
    # @param arch [String] Architecture for the target format; one of the ARCH_*
    # constants
    # @param plat [#index] platform
    # @param code [String] The shellcode for the resulting executable to run
    # @param fmt [String] One of the executable formats as defined in
    #   {.to_executable_fmt_formats}
    # @param exeopts [Hash] Passed directly to the appropriate method for
    #   generating an executable for the given +arch+/+plat+ pair.
    # @return [String] An executable appropriate for the given
    #   architecture/platform pair.
    # @return [nil] If the format is unrecognized or the arch and plat don't
    #   make sense together.
    def to_executable_fmt(framework, arch, plat, code, fmt, exeopts)
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

      # otherwise the result of this huge case statement is returned
      case fmt
      when 'asp'
        exe = to_executable_fmt(framework, arch, plat, code, 'exe-small', exeopts)
        Msf::Util::EXE.to_exe_asp(exe, exeopts)
      when 'aspx'
        Msf::Util::EXE.to_mem_aspx(framework, code, exeopts)
      when 'aspx-exe'
        exe = to_executable_fmt(framework, arch, plat, code, 'exe-small', exeopts)
        Msf::Util::EXE.to_exe_aspx(exe, exeopts)
      when 'dll'
        case arch
        when ARCH_X86, nil
          to_win32pe_dll(framework, code, exeopts)
        when ARCH_X64
          to_win64pe_dll(framework, code, exeopts)
        end
      when 'exe'
        case arch
        when ARCH_X86, nil
          to_win32pe(framework, code, exeopts)
        when ARCH_X64
          to_win64pe(framework, code, exeopts)
        end
      when 'exe-service'
        case arch
        when ARCH_X86, nil
          to_win32pe_service(framework, code, exeopts)
        when ARCH_X64
          to_win64pe_service(framework, code, exeopts)
        end
      when 'exe-small'
        case arch
        when ARCH_X86, nil
          to_win32pe_old(framework, code, exeopts)
        when ARCH_X64
          to_win64pe(framework, code, exeopts)
        end
      when 'exe-only'
        case arch
        when ARCH_X86, nil
          to_winpe_only(framework, code, exeopts)
        when ARCH_X64
          to_winpe_only(framework, code, exeopts, arch)
        end
      when 'msi'
        case arch
        when ARCH_X86, nil
          exe = to_win32pe(framework, code, exeopts)
        when ARCH_X64
          exe = to_win64pe(framework, code, exeopts)
        end
        exeopts[:uac] = true
        Msf::Util::EXE.to_exe_msi(framework, exe, exeopts)
      when 'msi-nouac'
        case arch
        when ARCH_X86, nil
          exe = to_win32pe(framework, code, exeopts)
        when ARCH_X64
          exe = to_win64pe(framework, code, exeopts)
        end
        Msf::Util::EXE.to_exe_msi(framework, exe, exeopts)
      when 'elf'
        if elf? code
          return code
        end

        if !plat || plat.index(Msf::Module::Platform::Linux)
          case arch
          when ARCH_X86, nil
            to_linux_x86_elf(framework, code, exeopts)
          when ARCH_X64
            to_linux_x64_elf(framework, code, exeopts)
          when ARCH_AARCH64
            to_linux_aarch64_elf(framework, code, exeopts)
          when ARCH_ARMLE
            to_linux_armle_elf(framework, code, exeopts)
          when ARCH_ARMBE
            to_linux_armbe_elf(framework, code, exeopts)
          when ARCH_MIPSBE
            to_linux_mipsbe_elf(framework, code, exeopts)
          when ARCH_MIPSLE
            to_linux_mipsle_elf(framework, code, exeopts)
          when ARCH_MIPS64
            to_linux_mips64_elf(framework, code, exeopts)
          when ARCH_RISCV32LE
            to_linux_riscv32le_elf(framework, code, exeopts)
          when ARCH_RISCV64LE
            to_linux_riscv64le_elf(framework, code, exeopts)
          when ARCH_PPC64LE
            to_linux_ppc64le_elf(framework, code, exeopts)
          when ARCH_PPC
            to_linux_ppc_elf(framework, code, exeopts)
          when ARCH_PPCE500V2
            to_linux_ppce500v2_elf(framework, code, exeopts)
          when ARCH_ZARCH
            to_linux_zarch_elf(framework, code, exeopts)
          when ARCH_LOONGARCH64
            to_linux_loongarch64_elf(framework, code, exeopts)
          end
        elsif plat && plat.index(Msf::Module::Platform::BSD)
          case arch
          when ARCH_X86, nil
            Msf::Util::EXE.to_bsd_x86_elf(framework, code, exeopts)
          when ARCH_X64
            Msf::Util::EXE.to_bsd_x64_elf(framework, code, exeopts)
          end
        elsif plat && plat.index(Msf::Module::Platform::Solaris)
          case arch
          when ARCH_X86, nil
            to_solaris_x86_elf(framework, code, exeopts)
          end
        end
      when 'elf-so'
        if elf? code
          return code
        end

        if !plat || plat.index(Msf::Module::Platform::Linux)
          case arch
          when ARCH_X86
            to_linux_x86_elf_dll(framework, code, exeopts)
          when ARCH_X64
            to_linux_x64_elf_dll(framework, code, exeopts)
          when ARCH_ARMLE
            to_linux_armle_elf_dll(framework, code, exeopts)
          when ARCH_AARCH64
            to_linux_aarch64_elf_dll(framework, code, exeopts)
          when ARCH_RISCV32LE
            to_linux_riscv32le_elf_dll(framework, code, exeopts)
          when ARCH_RISCV64LE
            to_linux_riscv64le_elf_dll(framework, code, exeopts)
          when ARCH_LOONGARCH64
            to_linux_loongarch64_elf_dll(framework, code, exeopts)
          end
        end
      when 'macho', 'osx-app'
        if macho? code
          macho = code
        else
          macho = case arch
                  when ARCH_X86, nil
                    to_osx_x86_macho(framework, code, exeopts)
                  when ARCH_X64
                    to_osx_x64_macho(framework, code, exeopts)
                  when ARCH_ARMLE
                    to_osx_arm_macho(framework, code, exeopts)
                  when ARCH_PPC
                    to_osx_ppc_macho(framework, code, exeopts)
                  when ARCH_AARCH64
                    to_osx_aarch64_macho(framework, code, exeopts)
                  end
        end
        fmt == 'osx-app' ? Msf::Util::EXE.to_osx_app(macho) : macho
      when 'vba'
        Msf::Util::EXE.to_vba(framework, code, exeopts)
      when 'vba-exe'
        exe = to_executable_fmt(framework, arch, plat, code, 'exe-small', exeopts)
        Msf::Util::EXE.to_exe_vba(exe)
      when 'vba-psh'
        Msf::Util::EXE.to_powershell_vba(framework, arch, code)
      when 'vbs'
        exe = to_executable_fmt(framework, arch, plat, code, 'exe-small', exeopts)
        Msf::Util::EXE.to_exe_vbs(exe, exeopts.merge({ persist: false }))
      when 'loop-vbs'
        exe = to_executable_fmt(framework, arch, plat, code, 'exe-small', exeopts)
        Msf::Util::EXE.to_exe_vbs(exe, exeopts.merge({ persist: true }))
      when 'jsp'
        arch ||= [ ARCH_X86 ]
        tmp_plat = plat.platforms if plat
        tmp_plat ||= Msf::Module::PlatformList.transform('win')
        tmp_fmt = 'elf'
        tmp_fmt = 'exe' if tmp_plat.index(Msf::Module::Platform::Windows)
        tmp_fmt = 'macho' if tmp_plat.index(Msf::Module::Platform::OSX)
        exe = Msf::Util::EXE.to_executable(framework, arch, tmp_plat, code, tmp_fmt, exeopts)
        Msf::Util::EXE.to_jsp(exe)
      when 'war'
        arch ||= [ ARCH_X86 ]
        tmp_plat = plat.platforms if plat
        tmp_plat ||= Msf::Module::PlatformList.transform('win')
        tmp_fmt = 'elf'
        tmp_fmt = 'exe' if tmp_plat.index(Msf::Module::Platform::Windows)
        tmp_fmt = 'macho' if tmp_plat.index(Msf::Module::Platform::OSX)
        exe = Msf::Util::EXE.to_executable(framework, arch, tmp_plat, code, tmp_fmt, exeopts)
        Msf::Util::EXE.to_jsp_war(exe)
      when 'psh'
        Msf::Util::EXE.to_win32pe_psh(framework, code, exeopts)
      when 'psh-net'
        Msf::Util::EXE.to_win32pe_psh_net(framework, code, exeopts)
      when 'psh-reflection'
        Msf::Util::EXE.to_win32pe_psh_reflection(framework, code, exeopts)
      when 'psh-cmd'
        Msf::Util::EXE.to_powershell_command(framework, arch, code)
      when 'hta-psh'
        Msf::Util::EXE.to_powershell_hta(framework, arch, code)
      when 'python-reflection'
        Msf::Util::EXE.to_python_reflection(framework, arch, code, exeopts)
      when 'ducky-script-psh'
        Msf::Util::EXE.to_powershell_ducky_script(framework, arch, code)
      end
    end

    # encode_stub
    #
    # @param framework [Msf::Framework]
    # @param arch     [String]
    # @param code     [String]
    # @param platform [String]
    # @param badchars [String]
    def encode_stub(framework, arch, code, platform = nil, badchars = '')
      return code unless framework.encoders

      framework.encoders.each_module_ranked('Arch' => arch) do |name, _mod|
        enc = framework.encoders.create(name)
        raw = enc.encode(code, badchars, nil, platform)
        return raw if raw
      rescue StandardError
      end
      nil
    end

    def self.generate_nops(framework, arch, len, opts = {})
      opts['BadChars'] ||= ''
      opts['SaveRegisters'] ||= [ 'esp', 'ebp', 'esi', 'edi' ]

      return nil unless framework.nops

      framework.nops.each_module_ranked('Arch' => arch) do |name, _mod|
        nop = framework.nops.create(name)
        raw = nop.generate_sled(len, opts)
        return raw if raw
      rescue StandardError
        # @TODO: stop rescuing everying on each of these, be selective
      end
      nil
    end

    


    # FMT Formats
    # self.to_executable_fmt_formats
    # @return [Array] Returns an array of strings
    def to_executable_fmt_formats
      [
        'asp',
        'aspx',
        'aspx-exe',
        'axis2',
        'dll',
        'ducky-script-psh',
        'elf',
        'elf-so',
        'exe',
        'exe-only',
        'exe-service',
        'exe-small',
        'hta-psh',
        'jar',
        'jsp',
        'loop-vbs',
        'macho',
        'msi',
        'msi-nouac',
        'osx-app',
        'psh',
        'psh-cmd',
        'psh-net',
        'psh-reflection',
        'python-reflection',
        'vba',
        'vba-exe',
        'vba-psh',
        'vbs',
        'war'
      ]
    end
  end

  class << self
    include ClassMethods
  end
end
