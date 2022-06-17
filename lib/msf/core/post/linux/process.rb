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

  def mem_search_ascii(pid, min_search_len, max_search_len, needles)
    # use current process
    if pid.nil?
      pid = 0
    end

    proc_id = session.sys.process.open(pid)
    matches = proc_id.memory.search(min_search_len, max_search_len, needles)
  end

  def mem_read(pid = nil, base_address, length)
    if pid.nil?
      pid = 0
    end

    proc_id = session.sys.process.open(pid)
    data = proc_id.memory.read(base_address, length)
  end

end # Process
end # Linux
end # Post
end # Msf
