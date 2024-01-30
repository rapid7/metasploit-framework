# -*- coding: binary -*-


module Msf
class Post
module Linux

module Process

  include Msf::Post::Process

  def initialize(info = {})
    super(
      update_info(
        info,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_process_attach
              stdapi_sys_process_memory_read
            ]
          }
        }
      )
    )
  end

  def mem_read(base_address, length, pid: 0)
    proc_id = session.sys.process.open(pid, PROCESS_READ)
    data = proc_id.memory.read(base_address, length)
  end

end # Process
end # Linux
end # Post
end # Msf
