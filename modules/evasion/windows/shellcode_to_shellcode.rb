class MetasploitModule < Msf::Evasion

  include Msf::ModuleInputs::Payload
  include Msf::ModuleOutputs::Payload

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Mock shellcode to shellcode evasion module',
        'Description' => %q{...},
        'Author' => [ 'sjanusz-r7' ],
        'License' => MSF_LICENSE,
        'Platform' => 'windows',
        'Arch' => [ARCH_X86, ARCH_X64]
      )
    )
  end

  # For now, return the same shellcode we were provided, as a mock.
  def run
    # Let's pretend that payload.encoded here will be modified.
    payload.encoded
  end
end
