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
        'Description' => 'Execute a Python payload from a command',
        'Author' => 'Spencer McIntyre',
        'Platform' => 'win',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_PYTHON,
        'AdaptedPlatform' => 'python',
        'RequiredCmd' => 'python'
      )
    )
    register_advanced_options(
      [
        OptString.new('PythonPath', [true, 'The path to the Python executable', 'python'])
      ]
    )
  end

  def compatible?(mod)
    # size is not unlimited due to the standard command length limit, the final size depends on the options that are
    # configured but 3,000 is in a good range (can go up to 4,000 with default settings at this time)
    if mod.type == Msf::MODULE_PAYLOAD && (mod.class.const_defined?(:CachedSize) && mod.class::CachedSize != :dynamic) && (mod.class::CachedSize >= 3_000)
      return false
    end

    super
  end

  def generate
    payload = super

    if payload.include?("\n")
      payload = Msf::Payload::Python.create_exec_stub(payload)
    end

    "#{datastore['PythonPath']} -c \"#{payload}\""
  end
end
