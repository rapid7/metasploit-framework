# -*- coding: binary -*-
require 'msf/core'
require 'macho'

class Msf::Payload::MachO

  def initialize(data)
    @macho = MachO::MachOFile.new_from_bin(data)
  end

  def entrypoint
    main_func = @macho[:LC_MAIN].first
    main_func.entryoff
  end

  #
  # Return the VM respresentation of macho file
  #
  def flatten
    raw_data = @macho.serialize
    min = -1
    max = 0
    for segment in @macho.segments
      next if segment.segname == MachO::LoadCommands::SEGMENT_NAMES[:SEG_PAGEZERO]
      if min == -1 or min > segment.vmaddr
        min = segment.vmaddr
      end
      if max < segment.vmaddr + segment.vmsize
        max = segment.vmaddr + segment.vmsize
      end
    end

    output_data = "\x00" * (max - min)
    for segment in @macho.segments
      for section in segment.sections
        flat_addr = section.addr - min
        section_data = raw_data[section.offset, section.size]
        if section_data
          output_data[flat_addr, section_data.size] = section_data
        end
      end
    end

    output_data
  end

end

