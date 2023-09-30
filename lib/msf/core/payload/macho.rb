# -*- coding: binary -*-
require 'macho'
require 'digest'

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

  # See: https://github.com/apple-oss-distributions/libsecurity_codesigning/blob/main/lib/signer.cpp#L179
  # See: https://github.com/indygreg/apple-platform-rs/blob/main/apple-codesign/src/code_directory.rs
  # See: https://developer.apple.com/forums/thread/702351
  # See: https://github.com/apple-oss-distributions/Security/blob/e4ea024c9bbd3bfda30ec6df270bfb4c7438d1a9/SecurityTool/sharedTool/codesign.c#L323
  def sign
    raw_data = @macho.serialize
    code_signature_index = @macho[:LC_CODE_SIGNATURE][0].dataoff
    code_signature = raw_data[code_signature_index..]
    s_magic, s_length, s_count, code_indexes = code_signature.unpack("N3a*")
    raise "Invalid kSecCodeMagicEmbeddedSignature magic for macho" if s_magic != 0xfade0cc0
    indexes = code_indexes.unpack("N#{s_count*2}a*")
    code_directory = indexes.pop
    magic, length, version, flags, hash_offset, ident_offset, n_special_slots, n_code_slots, code_limit, hash_size, hash_type, platform, page_size, spare2, hash_list = code_directory.unpack("N9C4Na*")
    raise "Invalid kSecCodeMagicCodeDirectory magic for macho" if magic != 0xfade0c02
    pagesize = 2**page_size
    page_index = 0
    raw_data.bytes.each_slice(pagesize) do |page|
      break if page_index >= (length-hash_offset)/(hash_size)
      if (page_index+1)*pagesize > code_signature_index
        page = page[0..(pagesize-((page_index+1)*pagesize-code_signature_index))-1]
      end
      new_digest = Digest::SHA256.digest(page.pack("C*"))
      old_digest_index = code_signature.index(code_directory[hash_offset+(hash_size*page_index)...])
      code_signature[old_digest_index..old_digest_index+hash_size-1] = new_digest
      page_index += 1
    end
    raw_data[code_signature_index..] = code_signature
    raw_data
  end

  def raw
    @macho.serialize
  end

end

