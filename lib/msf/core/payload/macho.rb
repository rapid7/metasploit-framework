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
  # Return the VM respresentation of a macho file
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

  def to_dylib(name)
    new_lc = MachO::LoadCommands::LoadCommand.create(:LC_ID_DYLIB, "@executable_path/#{name}.dylib", 0, 0, 0)
    @macho.add_command(new_lc)

    raw_data = @macho.serialize
    raw_data[12] = MachO::Headers::MH_DYLIB.chr
    raw_data[36,7] = "__ZERO\x00"
    raw_data
  end

  def raw
    @macho.serialize
  end

end

