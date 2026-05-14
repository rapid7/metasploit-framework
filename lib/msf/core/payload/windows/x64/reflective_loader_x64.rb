module Msf::Payload::Windows::ReflectiveLoaderX64

  def reflective_loader(opts = {})
    iv = opts.fetch(:iv) { rand(0x100000000) }

    reflective_loader_asm = Rex::Payloads::Shuffle.from_graphml_file(
      File.join(Msf::Config.install_root, 'data', 'shellcode', 'reflective_loader.x64.graphml'),
      arch: ARCH_X64,
      name: 'reflective_loader'
    )
    
    # Patch the assembly to set the correct IV
    # db 0x41, 0xb9, 0x00, 0x00, 0x00, 0x00  =>  mov r9d, <iv>
    # iv_bytes = [iv].pack('V').bytes.map { |b| "0x%02x" % b }.join(', ')
    # unless asm.include?("db 0x41, 0xb9, 0x00, 0x00, 0x00, 0x00")
    #   raise "Failed to patch block_api assembly with IV 0x#{iv.to_s(16).rjust(8, '0')} (#{iv_bytes})"
    # end
    # asm.sub!("db 0x41, 0xb9, 0x00, 0x00, 0x00, 0x00", "db 0x41, 0xb9, #{iv_bytes}")


    code = Metasm::Shellcode.assemble(Metasm::X64.new, reflective_loader_asm).encode_string
    hash = Rex::Text.md5_raw(code).unpack("H*").first
    vprint_status("Reflective Loader GraphML fingerprint: #{hash}")
    code
  end
end