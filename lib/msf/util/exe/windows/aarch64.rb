module Msf::Util::EXE::Windows::Aarch64

  def to_executable(framework, code, opts = {}, fmt = 'exe')
    return to_winaarch64pe(framework, code, opts) if fmt == 'exe'
    nil
  end

  # Construct a Windows AArch64 PE executable with the given shellcode.
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
    pe[bo, code.length] = code.dup
    pe
  end
end