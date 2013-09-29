##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


###
#
# This class implements single-byte NOP generation for X86.  It takes from
# ADMmutate and from spoonfu.
#
###
class Metasploit3 < Msf::Nop

SINGLE_BYTE_SLED =
  {
    # opcode  affected registers
    # ------  ------------------
    "\x90" => nil               , # nop
    "\x97" => [ 'eax', 'edi'   ], # xchg eax,edi
    "\x96" => [ 'eax', 'esi'   ], # xchg eax,esi
    "\x95" => [ 'eax', 'ebp'   ], # xchg eax,ebp
    "\x93" => [ 'eax', 'ebx'   ], # xchg eax,ebx
    "\x92" => [ 'eax', 'edx'   ], # xchg eax,edx
    "\x91" => [ 'eax', 'ecx'   ], # xchg eax,ecx
    "\x99" => [ 'edx'          ], # cdq
    "\x4d" => [ 'ebp'          ], # dec ebp
    "\x48" => [ 'eax'          ], # dec eax
    "\x47" => [ 'edi'          ], # inc edi
    "\x4f" => [ 'edi'          ], # dec edi
    "\x40" => [ 'eax'          ], # inc eax
    "\x41" => [ 'ecx'          ], # inc ecx
    "\x37" => [ 'eax'          ], # aaa
    "\x3f" => [ 'eax'          ], # aas
    "\x27" => [ 'eax'          ], # daa
    "\x2f" => [ 'eax'          ], # das
    "\x46" => [ 'esi'          ], # inc esi
    "\x4e" => [ 'esi'          ], # dec esi
    "\xfc" => nil               , # cld
    "\xfd" => nil               , # std
    "\xf8" => nil               , # clc
    "\xf9" => nil               , # stc
    "\xf5" => nil               , # cmc
    "\x98" => [ 'eax'          ], # cwde
    "\x9f" => [ 'eax'          ], # lahf
    "\x4a" => [ 'edx'          ], # dec edx
    "\x44" => [ 'esp', 'align' ], # inc esp
    "\x42" => [ 'edx'          ], # inc edx
    "\x43" => [ 'ebx'          ], # inc ebx
    "\x49" => [ 'ecx'          ], # dec ecx
    "\x4b" => [ 'ebx'          ], # dec ebx
    "\x45" => [ 'ebp'          ], # inc ebp
    "\x4c" => [ 'esp', 'align' ], # dec esp
    "\x9b" => nil               , # wait
    "\x60" => [ 'esp'          ], # pusha
    "\x0e" => [ 'esp', 'align' ], # push cs
    "\x1e" => [ 'esp', 'align' ], # push ds
    "\x50" => [ 'esp'          ], # push eax
    "\x55" => [ 'esp'          ], # push ebp
    "\x53" => [ 'esp'          ], # push ebx
    "\x51" => [ 'esp'          ], # push ecx
    "\x57" => [ 'esp'          ], # push edi
    "\x52" => [ 'esp'          ], # push edx
    "\x06" => [ 'esp', 'align' ], # push es
    "\x56" => [ 'esp'          ], # push esi
    "\x54" => [ 'esp'          ], # push esp
    "\x16" => [ 'esp', 'align' ], # push ss
    "\x58" => [ 'esp', 'eax'   ], # pop eax
    "\x5d" => [ 'esp', 'ebp'   ], # pop ebp
    "\x5b" => [ 'esp', 'ebx'   ], # pop ebx
    "\x59" => [ 'esp', 'ecx'   ], # pop ecx
    "\x5f" => [ 'esp', 'edi'   ], # pop edi
    "\x5a" => [ 'esp', 'edx'   ], # pop edx
    "\x5e" => [ 'esp', 'esi'   ], # pop esi
    "\xd6" => [ 'eax'          ], # salc
  }

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Single Byte',
            'Alias'       => 'ia32_singlebyte',
            'Description' => 'Single-byte NOP generator',
            'Author'      => 'spoonm',
            'License'     => MSF_LICENSE,
            'Arch'        => ARCH_X86
        )
    )

    register_advanced_options(
      [
        OptBool.new('RandomNops', [ false, "Generate a random NOP sled", true ])
      ], self.class)
  end

  # Generate a single-byte NOP sled for X86
  def generate_sled(length, opts = {})
    sled_hash    = SINGLE_BYTE_SLED
    sled_max_idx = sled_hash.length
    sled_cur_idx = 0
    out_sled     = ''

    random   = opts['Random']
    badchars = opts['BadChars']      || ''
    badregs  = opts['SaveRegisters'] || []

    # Did someone specify random NOPs in the environment?
    if (!random and datastore['RandomNops'])
      random = (datastore['RandomNops'].match(/true|1|y/i) != nil)
    end

    # Generate the whole sled...
    1.upto(length) { |current|

      cur_char  = nil
      threshold = 0

      # Keep snagging characters until we find one that satisfies both the
      # bad character and bad register requirements
      begin
        sled_cur_idx  = rand(sled_max_idx) if (random == true)
        cur_char      = sled_hash.keys[sled_cur_idx]
        sled_cur_idx += 1 if (random == false)
        sled_cur_idx  = 0 if (sled_cur_idx >= sled_max_idx)

        # Make sure that we haven't gone over the sled repeat threshold
        if ((threshold += 1) > self.nop_repeat_threshold)
          return nil
        end

      end while ((badchars.include?(cur_char)) or
        ((sled_hash[cur_char]) and
          ((sled_hash[cur_char] & badregs).length > 0)))

      # Add the character to the sled now that it's passed our checks
      out_sled += cur_char
    }

    # If the sled fails to entirely generate itself, then that's bogus,
    # man...
    if (out_sled.length != length)
      return nil
    end

    return out_sled
  end

end
