#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin: allow patching the file from the dasm interface
# use P to assemble a new instruction at the current address

# backup the executable file
def backup_program_file
  f = @program.filename
  if File.exist?(f) and not File.exist?(f + '.bak')
    File.open(f + '.bak', 'wb') { |wfd|
      File.open(f, 'rb') { |rfd|
        while buf = rfd.read(1<<16)
          wfd.write buf
        end
      }
    }
  end
end

# create a backup and reopen the backend VirtualFile RW
def reopen_rw(addr=nil, edata=nil)
  if not edata
    sections.each { |k, v| reopen_rw(k, v) }
    return true
  end

  return if not File.writable?(@program.filename)
  backup_program_file
  if not edata.data.kind_of? VirtualFile
    # section too small, loaded as real String
    # force reopen as VFile (allow hexediting in gui)
    return if not off = addr_to_fileoff(addr)
    len = edata.data.length
    edata.data = VirtualFile.read(@program.filename, 'rb+').dup(off, len)
  else
    edata.data.fd.reopen @program.filename, 'rb+'
  end
end

raise "cant find original file" if not @program.filename or not File.exist? @program.filename

reopen_rw

def patch_instrs(addr, asmsrc)
  sc = Metasm::Shellcode.new(cpu, addr)	# pfx needed for autorequire
  sc.assemble(asmsrc, cpu)
  sc.encoded.fixup! prog_binding	# allow references to dasm labels in the shellcode
  raw = sc.encode_string

  if s = get_section_at(addr) and s[0].data.kind_of? VirtualFile
    s[0][s[0].ptr, raw.length] = raw
  elsif o = addr_to_fileoff(addr)	# section too small, not loaded as a VirtFile
    backup_program_file
    File.open(@program.filename, 'rb+') { |fd|
      fd.pos = o
      fd.write raw
    }
    s[0][s[0].ptr, raw.length] = raw if s
  else
    return
  end

  b = split_block(addr)

  # clear what we had in the rewritten space
  raw.length.times { |rawoff|
    next if not di = di_at(addr+rawoff)
    di.block.list.each { |ldi| @decoded.delete ldi.address }
  }

  disassemble_fast(addr) if b
  if b and @decoded[addr]
    nb = @decoded[addr].block
    nb.from_normal = b.from_normal
    nb.from_subfuncret = b.from_subfuncret
    nb.from_indirect = b.from_indirect
  end
  true
end

if gui
  gui.keyboard_callback[?P] = lambda { |k|
    addr = gui.curaddr
    gui.inputbox('new instructions') { |src|
      src = src.gsub(/;\s+/, "\n")
      patch_instrs(addr, src)
      gui.gui_update
    }
    true
  }
end
