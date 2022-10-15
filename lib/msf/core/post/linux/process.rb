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
              stdapi_sys_process_memory_search
            ]
          }
        }
      )
    )
  end

  def mem_search_ascii(min_search_len, max_search_len, needles, pid: 0)
    proc_id = session.sys.process.open(pid, PROCESS_READ)
    matches = proc_id.memory.search(needles, min_search_len, max_search_len)
  end

  def mem_read(base_address, length, pid: 0)
    proc_id = session.sys.process.open(pid, PROCESS_READ)
    data = proc_id.memory.read(base_address, length)
  end

end # Process
end # Linux
end # Post
end # Msf
