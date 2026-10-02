# -*- coding: binary -*-
module Msf::Util::EXE::Windows::Aarch64
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Windows::Common

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    # The size, in bytes, of the fixed `payload[]` buffer declared in
    # data/templates/src/pe/exe/template_aarch64_windows.c and
    # data/templates/src/pe/dll/template_aarch64_windows.c (SCSIZE). Shellcode
    # longer than this would overwrite adjacent bytes in the compiled template.
    WINAARCH64_PAYLOAD_SPACE = 8192

    # Construct a Windows AArch64 PE executable with the given shellcode.
    #
    # There is still no dedicated AArch64 service template, so this loader-style
    # EXE is reused when a caller asked for exe-service. That is safe for
    # psexec-style delivery: Windows still spawns the process when the SCM
    # start request times out because the binary doesn't speak the service
    # control protocol. DLL generation uses {#to_winaarch64pe_dll} instead.
    #
    # @param framework [Msf::Framework] The Metasploit framework instance.
    # @param code [String] The shellcode to embed in the executable.
    # @param opts [Hash] Additional options.
    # @return [String] The constructed PE executable as a binary string.
    def to_winaarch64pe(framework, code, opts = {})
      inject_winaarch64_payload(code, opts, 'template_aarch64_windows.exe')
    end

    # Construct a Windows AArch64 PE DLL with the given shellcode.
    #
    # @param framework [Msf::Framework] The Metasploit framework instance.
    # @param code [String] The shellcode to embed in the DLL.
    # @param opts [Hash] Additional options.
    # @raise [RuntimeError] if opts[:inject] is set, which is unsupported.
    # @return [String] The constructed PE DLL as a binary string.
    def to_winaarch64pe_dll(framework, code, opts = {})
      if opts[:inject]
        raise RuntimeError, 'Template injection unsupported for AArch64 DLLs'
      end

      inject_winaarch64_payload(code, opts, 'template_aarch64_windows.dll')
    end

    # Overwrite the "PAYLOAD:" tag in a Windows AArch64 PE template.
    #
    # @param code [String] The shellcode to embed.
    # @param opts [Hash] Options that may include a custom :template path.
    # @param default_template [String] Template filename used when none is set.
    # @raise [RuntimeError] if the template is missing the PAYLOAD: tag or the
    #   payload is larger than WINAARCH64_PAYLOAD_SPACE.
    # @return [String] The PE image with the payload substituted in.
    def inject_winaarch64_payload(code, opts, default_template)
      set_template_default(opts, default_template)

      pe = File.read(opts[:template], mode: 'rb')
      bo = find_payload_tag(pe, 'Invalid Windows AArch64 template: missing "PAYLOAD:" tag')

      if code.length > WINAARCH64_PAYLOAD_SPACE
        raise RuntimeError, "The Windows AArch64 PE generator has a max size of #{WINAARCH64_PAYLOAD_SPACE} bytes, please fix the calling module"
      end

      pe[bo, code.length] = code.dup
      pe
    end
  end

  class << self
    include ClassMethods
  end
end
