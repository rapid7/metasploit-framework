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
      'PrependFork' => [false, 'Prepend a stub that starts the payload in its own process via fork', 'false'],
      'PrependSetresuid' => [false, 'Prepend a stub that executes the setresuid(0, 0, 0) system call', 'false'],
      'PrependSetreuid' => [false, 'Prepend a stub that executes the setreuid(0, 0) system call', 'false'],
      'PrependSetuid' => [false, 'Prepend a stub that executes the setuid(0) system call', 'false'],
      'PrependSetresgid' => [false, 'Prepend a stub that executes the setresgid(0, 0, 0) system call', 'false'],
      'PrependSetregid' => [false, 'Prepend a stub that executes the setregid(0, 0) system call', 'false'],
      'PrependSetgid' => [false, 'Prepend a stub that executes the setgid(0) system call', 'false'],
      'PrependChrootBreak' => [false, 'Prepend a stub that will break out of a chroot (includes setreuid to root)', 'false'],
      'AppendExit' => [false, 'Prepend a stub that will break out of a chroot (includes setreuid to root)', 'false']
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
    pre = ''
    app = ''
    for name in prepends_order.each
      pre << prepends_map.fetch(name) if datastore[name]
    end
    for name in appends_order.each
      app << appends_map.fetch(name) if datastore[name]
    end
    pre.force_encoding('ASCII-8BIT') +
      buf.force_encoding('ASCII-8BIT') +
      app.force_encoding('ASCII-8BIT')
  end
end
