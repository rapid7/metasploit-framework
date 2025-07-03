
# Linux Multi shared logic.
#
module Msf::Payload::Linux::MultiArch
  def initialize(info = {})
    super
    register_options(
      [
        Msf::OptEnum.new('REQUESTED_ARCH', [true, 'The desired architecture of the returned payload.', 'NONE', [ 'NONE', 'ARCH_AARCH64', 'ARCH_ARMBE', 'ARCH_ARMLE', 'ARCH_MIPS64', 'ARCH_MIPSBE', 'ARCH_MIPSLE', 'ARCH_PPC', 'ARCH_PPCE500V2', 'ARCH_PPC64LE', 'ARCH_X64', 'ARCH_X86', 'ARCH_ZARCH' ]]),
      ]
    )
  end

  def generate_payload_uuid(conf = {})
    conf[:arch] = metasploit_arch_transform(desired_arch(conf))
    super
  end

  def include_send_uuid
    true
  end

  def mettle_arch_transform(arch)
    case arch
    when ARCH_AARCH64, 'ARCH_AARCH64'
      return 'aarch64-linux-musl'
    when ARCH_ARMBE, 'ARCH_ARMBE'
      return 'armv5b-linux-musleabi'
    when ARCH_ARMLE, 'ARCH_ARMLE'
      return 'armv5l-linux-musleabi'
    when ARCH_MIPS64, 'ARCH_MIPS64'
      return 'mips64-linux-muslsf'
    when ARCH_MIPSBE, 'ARCH_MIPSBE'
      return 'mips-linux-muslsf'
    when ARCH_MIPSLE, 'ARCH_MIPSLE'
      return 'mipsel-linux-muslsf'
    when ARCH_PPC, 'ARCH_PPC'
      return 'powerpc-linux-muslsf'
    when ARCH_PPCE500V2, 'ARCH_PPCE500V3'
      return 'powerpc-e500v2-linux-musl'
    when ARCH_PPC64LE, 'ARCH_PPC64LE'
      return 'powerpc64le-linux-musl'
    when ARCH_X64, 'ARCH_X86'
      return 'x86_64-linux-musl'
    when ARCH_X86, 'ARCH_X86'
      return 'i486-linux-musl'
    when ARCH_ZARCH, 'ARCH_ZARCH'
      return 's390x-linux-musl'
    else
      return nil
    end
  end

  def metasploit_arch_transform(arch)
    case arch
    when ARCH_AARCH64, 'ARCH_AARCH64'
      return ARCH_AARCH64
    when ARCH_ARMBE, 'ARCH_ARMBE'
      return ARCH_ARMBE
    when ARCH_ARMLE, 'ARCH_ARMLE'
      return ARCH_ARMLE
    when ARCH_MIPS64, 'ARCH_MIPS64'
      return ARCH_MIPS64
    when ARCH_MIPSBE, 'ARCH_MIPSBE'
      return ARCH_MIPSBE
    when ARCH_MIPSLE, 'ARCH_MIPSLE'
      return ARCH_MIPSLE
    when ARCH_PPC, 'ARCH_PPC'
      return ARCH_PPC
    when ARCH_PPCE500V2, 'ARCH_PPCE500V3'
      return ARCH_PPCE500V2
    when ARCH_PPC64LE, 'ARCH_PPC64LE'
      return ARCH_PPC64LE
    when ARCH_X64, 'ARCH_X86'
      return ARCH_X64
    when ARCH_X86, 'ARCH_X86'
      return ARCH_X86
    when ARCH_ZARCH, 'ARCH_ZARCH'
      return ARCH_ZARCH
    else
      return nil
    end
  end

  def desired_arch(opts = {})
    if datastore.include?('REQUESTED_ARCH') && datastore['REQUESTED_ARCH'] != 'NONE'
      return_arch = datastore['REQUESTED_ARCH']
    else
      return_arch = opts[:arch]
    end
    return_arch
  end
end
