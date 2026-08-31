# -*- coding: binary -*-
module Msf::Util::EXE::Windows::Aarch64
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Windows::Common

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    # The size, in bytes, of the fixed `payload[]` buffer declared in
    # data/templates/src/pe/exe/template_aarch64_windows.c (SCSIZE). Shellcode
    # longer than this would overwrite adjacent bytes in the compiled template.
    WINAARCH64_PAYLOAD_SPACE = 8192

    # Construct a Windows AArch64 PE executable with the given shellcode.
    #
    # Unlike the x86/x64 templates, there is currently no dedicated "service"
    # or "dll" AArch64 template, so this loader-style template (which copies
    # the payload into RWX memory and runs it in a new thread) is reused
    # wherever an AArch64 PE is requested, including when a caller asked for
    # an exe-service. That is safe for psexec-style delivery: Windows still
    # spawns the process when the SCM start request times out because the
    # binary doesn't speak the service control protocol.
    # to_winaarch64pe
    #
    # @param framework [Msf::Framework] The Metasploit framework instance.
    # @param code [String] The shellcode to embed in the executable.
    # @param opts [Hash] Additional options.
    # @return [String] The constructed PE executable as a binary string.

    def to_winaarch64pe(framework, code, opts = {})
      # Use the standard template if not specified by the user.
      # This helper finds the full path and stores it in opts[:template].
      set_template_default(opts, 'template_aarch64_windows.exe')

      # Read the template directly from the path now stored in the options.
      pe = File.read(opts[:template], mode: 'rb')

      # Find the tag and inject the payload
      bo = find_payload_tag(pe, 'Invalid Windows AArch64 template: missing "PAYLOAD:" tag')

      if code.length > WINAARCH64_PAYLOAD_SPACE
        raise RuntimeError, "The Windows AArch64 EXE generator has a max size of " \
                             "#{WINAARCH64_PAYLOAD_SPACE} bytes, please fix the calling module"
      end

      pe[bo, code.length] = code.dup
      pe
    end
  end

  class << self
    include ClassMethods
  end
end
