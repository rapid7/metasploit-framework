# -*- coding: binary -*-

require 'rex/post'

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

        #
        # Reads a specified length of memory from a given base address of a process
        #
        # @param base_address [Integer] the starting address to read from
        # @param length [Integer] the number of bytes to read
        # @param pid [Integer] the process ID (optional, default is 0)
        # @return [String] the read memory content
        #
        def mem_read(base_address, length, pid: 0)
          proc_id = session.sys.process.open(pid, PROCESS_READ)
          proc_id.memory.read(base_address, length)
        end
      end
    end
  end
end
