# -*- coding: binary -*-

module Rex
module ElfScan
module Search

  class DumpRVA
    attr_accessor :elf

    def initialize(elf)
      self.elf = elf
    end

    def config(param)
      @address = param['args']
    end

    def scan(param)
      config(param)

      $stdout.puts "[#{param['file']}]"

      # Adjust based on -A and -B flags
      pre = param['before'] || 0
      suf = param['after']  || 16

      @address -= pre
      @address = 0 if (@address < 0 || ! @address)
      buf = elf.read_rva(@address, suf)
      $stdout.puts elf.ptr_s(@address) + " " + buf.unpack("H*")[0]
    end
  end

  class DumpOffset < DumpRVA
    def config(param)
      begin
        @address = elf.offset_to_rva(param['args'])
      rescue Rex::ElfParsey::BoundsError
      end
    end
  end
end
end
end
