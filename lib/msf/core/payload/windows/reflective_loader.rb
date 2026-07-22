module Msf::Payload::Windows::ReflectiveLoader
  include Msf::Payload::Windows::ReflectiveLoaderCommon

  # Assemble the polymorphic x86 reflective loader shellcode with a fresh
  # ROR13 IV. See {ReflectiveLoaderCommon#build_reflective_loader} for the
  # patching pipeline.
  #
  # @param opts [Hash]
  # @option opts [Integer] :iv 32-bit seed for ROR13 hashing (random when omitted)
  # @return [String] assembled and patched x86 reflective loader shellcode
  # @raise [ReflectiveLoaderCommon::Error] if an expected opcode pattern is missing from the shuffled assembly
  def reflective_loader(opts = {})
    build_reflective_loader(opts, {
      graphml_path:      File.join(Msf::Config.install_root, 'data', 'shellcode', 'reflective_loader.x86.graphml'),
      arch:              ARCH_X86,
      metasm_arch:       Metasm::X86,
      iv_patch_prefixes: ['db 0xbf,', 'db 0xb8,'],
      dll_hash_base:     'db 0x81, 0xff,'
    })
  end
end
