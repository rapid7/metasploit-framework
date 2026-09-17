require 'metasm'
require 'rex/text'

#
# Linux Preprends shared logic.
#
module Msf::Payload::Linux::Prepends
  def initialize(info)
    super(info)
    register_prepend_options
  end

  def register_prepend_options
    all_options = {
      'PrependExecOnce' => [false, 'Prepend a stub that runs the payload once per boot using a /dev/shm marker', 'false'],
      'PrependFork' => [false, 'Prepend a stub that starts the payload in its own process via fork', 'false'],
      'PrependSetresuid' => [false, 'Prepend a stub that executes the setresuid(0, 0, 0) system call', 'false'],
      'PrependSetreuid' => [false, 'Prepend a stub that executes the setreuid(0, 0) system call', 'false'],
      'PrependSetuid' => [false, 'Prepend a stub that executes the setuid(0) system call', 'false'],
      'PrependSetresgid' => [false, 'Prepend a stub that executes the setresgid(0, 0, 0) system call', 'false'],
      'PrependSetregid' => [false, 'Prepend a stub that executes the setregid(0, 0) system call', 'false'],
      'PrependSetgid' => [false, 'Prepend a stub that executes the setgid(0) system call', 'false'],
      'PrependChrootBreak' => [false, 'Prepend a stub that will break out of a chroot (includes setreuid to root)', 'false'],
      'AppendExit' => [false, 'Append a stub that executes the exit(0) system call', 'false']
    }
    avaiable_options = []
    for prepend in prepends_order
      avaiable_options.append(Msf::OptBool.new(prepend, all_options.fetch(prepend)))
    end
    for append in appends_order
      avaiable_options.append(Msf::OptBool.new(append, all_options.fetch(append)))
    end
    register_advanced_options(avaiable_options, Msf::Payload::Linux)
  end

  def apply_prepends(buf)
    ds = datastore
    pre = ''
    app = ''
    for name in prepends_order.each
      pre << prepends_map.fetch(name) if datastore[name]
    end
    for name in appends_order.each
      app << appends_map.fetch(name) if datastore[name]
    end
    if ds['PayloadLinuxMinKernel'] == '2.6' && (!pre.empty? || !app.empty?) && !staged?
      fail_with(Msf::Module::Failure::BadConfig, 'Prepend options only work with PayloadLinuxMinKernel = 3.17.')
    end
    pre.force_encoding('ASCII-8BIT') +
      buf.force_encoding('ASCII-8BIT') +
      app.force_encoding('ASCII-8BIT')
  end

  private

  def prepend_exec_once_path
    @prepend_exec_once_path ||= "/dev/shm/.msf-#{Rex::Text.rand_text_alpha_lower(12)}"
  end
end
