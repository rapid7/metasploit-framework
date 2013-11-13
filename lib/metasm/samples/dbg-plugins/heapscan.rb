#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm debugger plugin
# adds some heap_* functions to interract with the target heap chunks
# functions:
#  heap_scan, scan for malloc chunks in the heaps and xrefs between them
#  heap_scanstruct, scan for arrays/linkedlists in the chunk graph
#  heap_chunk [addr], display a chunk
#  heap_array [addr], display an array of chunks from their root
#  heap_list [addr], display a linkedlist
#  heap_strscan [str], scan the memory for a raw string, display chunks xrefs
#  heap_snap, make a snapshot of the currently displayed structure, hilight fields change


# use precompiled native version when available
$heapscan_dir = File.join(File.dirname(plugin_filename).gsub('\\', '/'), 'heapscan')
require File.join($heapscan_dir, 'heapscan')

fname = case OS.current.shortname
when 'linos'
  'compiled_heapscan_lin'
when 'winos'
  case OS.current.version[0]
  when 5; 'compiled_heapscan_win'
  when 6; 'compiled_heapscan_win7'
  end
end
fname = File.join($heapscan_dir, fname)
if not File.exist?(fname + '.so') and File.exist?(fname + '.c')
  puts "compiling native scanner..."
  exe = DynLdr.host_exe.compile_c_file(DynLdr.host_cpu, fname + '.c')
  DynLdr.compile_binary_module_hack(exe)
  exe.encode_file(fname + '.so', :lib)
end
require fname if File.exist?(fname + '.so')

def heapscan_time(s='')
  @heapscan_time ||= nil
  t = Time.now
  log s + ' %.2fs' % (t-@heapscan_time) if @heapscan_time and s != ''
  @heapscan_time = t
  Gui.main_iter if gui
end

def heap; @heap ; end
def heap=(h) ; @heap = h ; end

def heapscan_scan(xr=true)
  heaps = []
  mmaps = []
  libc = nil
  pr = os_process
  pr.mappings.each { |a, l, p, f|
    case f.to_s
    when /heap/
      heaps << [a, l]
    when /libc[^a-zA-Z]/
      libc ||= a if p == 'r-xp'
    when ''
      mmaps << [a, l]
    end
  }

  heapscan_time ''
  @disassembler.parse_c ''
  if pr and OS.current.name =~ /winos/i
    if OS.current.version[0] == 5
      @heap = WindowsHeap.new(self)
      @heap.cp = @disassembler.c_parser
      @heap.cp.parse_file File.join($heapscan_dir, 'winheap.h') unless @heap.cp.toplevel.struct['_HEAP']
    else
      @heap = Windows7Heap.new(self)
      @heap.cp = @disassembler.c_parser
      @heap.cp.parse_file File.join($heapscan_dir, 'winheap7.h') unless @heap.cp.toplevel.struct['_HEAP']
    end
    @heap.heaps = heaps
  else
    @heap = LinuxHeap.new(self)
    @heap.cp = @disassembler.c_parser
    @heap.mmaps = mmaps
    @heap.scan_libc(libc)
    heapscan_time "libc!main_arena #{'%x' % @heap.main_arena_ptr}"
  end

  hsz = 0
  (heaps + mmaps).each { |a, l|
    hsz += l
    @heap.range.update a => l
  }

  log "#{hsz/1024/1024}M heap"

  @heap.scan_chunks
  heapscan_time "#{@heap.chunks.length} chunks"
  return if not xr

  @heap.scan_chunks_xr
  heapscan_time "#{@heap.xrchunksto.length} src, #{@heap.xrchunksfrom.length} dst"
end

def heapscan_structs
  heapscan_time
  @heap.bucketize
  heapscan_time "#{@heap.buckets.length} buckets"

  @heap.find_arrays
  heapscan_time "#{@heap.allarrays.length} arrays (#{@heap.allarrays.flatten.length} elems)"

  @heap.find_linkedlists
  heapscan_time "#{@heap.alllists.length} lists (#{@heap.alllists.flatten.length} elems)"
end

def heapscan_kernels
  heapscan_time
  @heap.find_kernels
  heapscan_time "#{@heap.kernels.length} kernels"
end

def heapscan_roots
  heapscan_time
  @heap.find_roots
  heapscan_time "#{@heap.roots.length} roots"
end

def heapscan_graph
  heapscan_time
  @heap.dump_graph
  heapscan_time 'graph.gv'
end

def gui_show_list(addr)
  a = resolve(addr)
  #@heap.cp.parse("struct ptr { void *ptr; };") if not @heap.cp.toplevel.struct['ptr']
  h = @heap.linkedlists[a]
  off = h.keys.first
  lst = h[off]

  if not st = lst.map { |l| @heap.chunk_struct[l] }.compact.first
    st = Metasm::C::Struct.new
    st.name = "list_#{'%x' % lst.first}"
    st.members = []
    (@heap.chunks[lst.first] / 4).times { |i|
      n = "u#{i}"
      t = Metasm::C::BaseType.new(:int)
      if i == off/4
        n = "next"
        t = Metasm::C::Pointer.new(st)
      end
      st.members << Metasm::C::Variable.new(n, t)
    }
    @heap.cp.toplevel.struct[st.name] = st
  end
  lst.each { |l| @heap.chunk_struct[l] = st }

  $ghw.addr_struct = {}
  lst.each { |aa|
    $ghw.addr_struct[aa] = @heap.cp.decode_c_struct(st.name, @memory, aa)
  }
  gui.parent_widget.mem.focus_addr(lst.first, :graphheap)
end

def gui_show_array(addr)
  head = resolve(addr)
  e = @heap.xrchunksto[head].to_a.find { |ee| @heap.arrays[ee] and @heap.arrays[ee][head] }
  return if not e
  lst = @heap.arrays[e][head]

  if not st = @heap.chunk_struct[head]
    st = Metasm::C::Struct.new
    st.name = "array_#{'%x' % head}"
    st.members = []
    (@heap.chunks[head] / 4).times { |i|
      n = "u#{i}"
      v = @memory[head+4*i, 4].unpack('L').first
      if @heap.chunks[v]
        t = Metasm::C::Pointer.new(Metasm::C::BaseType.new(:void))
      else
        t = Metasm::C::BaseType.new(:int)
      end
      st.members << Metasm::C::Variable.new(n, t)
    }
    @heap.cp.toplevel.struct[st.name] ||= st
  end
  @heap.chunk_struct[head] = st

  $ghw.addr_struct = { head => @heap.cp.decode_c_struct(st.name, @memory, head) }

  if not st = lst.map { |l| @heap.chunk_struct[l] }.compact.first
    e = lst.first
    st = Metasm::C::Struct.new
    st.name = "elem_#{'%x' % head}"
    st.members = []
    (@heap.chunks[e] / 4).times { |i|
      n = "u#{i}"
      v = @memory[e+4*i, 4].unpack('L').first
      if @heap.chunks[v]
        t = Metasm::C::Pointer.new(Metasm::C::BaseType.new(:void))
      else
        t = Metasm::C::BaseType.new(:int)
      end
      st.members << Metasm::C::Variable.new(n, t)
    }
    @heap.cp.toplevel.struct[st.name] ||= st
  end
  lst.each { |l| @heap.chunk_struct[l] = st }

  lst.each { |aa|
    $ghw.addr_struct[aa] = @heap.cp.decode_c_struct(st.name, @memory, aa)
  }
  gui.parent_widget.mem.focus_addr(head, :graphheap)
end


if gui
  require File.join($heapscan_dir, 'graphheap')
  $ghw = Metasm::Gui::GraphHeapWidget.new(@disassembler, gui.parent_widget.mem)
  gui.parent_widget.mem.addview :graphheap, $ghw
  $ghw.show if $ghw.respond_to?(:show)

  gui.new_command('heap_scan', 'scan the heap(s)') { |*a| heapscan_scan ; $ghw.heap = @heap }
  gui.new_command('heap_scan_noxr', 'scan the heap(s), no xrefs') { |*a| heapscan_scan(false) ; $ghw.heap = @heap }
  gui.new_command('heap_scan_xronly', 'scan the heap(s) for xrefs') { |*a| $ghw.heap.scan_chunks_xr }
  gui.new_command('heap_scanstructs', 'scan the heap for arrays/lists') { |*a| heapscan_structs }
  gui.new_command('heap_list', 'show a linked list') { |a|
    if a.to_s != ''
      gui_show_list(a)
    else
      l = [['addr', 'len']]
      @heap.alllists.each { |al|
        l << [Expression[al.first], al.length]
      }
      gui.listwindow('lists', l) { |*aa| gui_show_list(aa[0][0]) }
    end
  }
  gui.new_command('heap_array', 'show an array') { |a|
    if a.to_s != ''
      gui_show_array(a)
    else
      l = [['addr', 'len']]
      @heap.allarrays.each { |al|
        l << [Expression[al.first], al.length]
      }
      gui.listwindow('arrays', l) { |*aa| gui_show_array(aa[0][0]) }
    end
  }
  gui.new_command('heap_chunk', 'show a chunk') { |a|
    a = resolve(a)
    gui.parent_widget.mem.focus_addr(a, :graphheap)
    $ghw.do_focus_addr(a)
  }
  gui.new_command('heap_strscan', 'scan a string') { |a|
    sa = pattern_scan(a)
    log "found #{sa.length} strings : #{sa.map { |aa| Expression[aa] }.join(' ')}"
    sa.each { |aa|
      next if not ck = @heap.find_chunk(aa)
      log "ptr #{Expression[aa]} in chunk #{Expression[ck]} (#{Expression[@heap.chunks[ck]]}) in list #{@heap.linkedlists && @heap.linkedlists[ck] && true} in array #{@heap.arrays[ck].map { |k, v| "#{Expression[k]} (#{v.length})" }.join(', ') if @heap.arrays and @heap.arrays[ck]}"
    }
  }
  gui.new_command('heap_ptrscan', 'scan a pointer') { |a|
    a = resolve(a)
    if @heap.chunks[a]
      pa = @heap.xrchunksfrom[a].to_a
    else
      pa = pattern_scan(Expression.encode_imm(a, @cpu.size/8, @cpu.endianness))
    end
    log "found #{pa.length} pointers : #{pa.map { |aa| Expression[aa] }.join(' ')}"
    pa.each { |aa|
      next if not ck = @heap.find_chunk(aa)
      log "ptr @#{Expression[aa]} in chunk #{Expression[ck]} (#{Expression[@heap.chunks[ck]]}) in list #{@heap.linkedlists && @heap.linkedlists[ck] && true} in array #{@heap.arrays[ck].map { |k, v| "#{Expression[k]} (#{v.length})" }.join(', ') if @heap.arrays and @heap.arrays[ck]}"
    }
  }

  gui.new_command('heap_snap', 'snapshot the current heap struct') { |a|
    $ghw.snap
  }
  gui.new_command('heap_snap_add', 'snapshot, ignore fields changed between now and last snap') { |a|
    $ghw.snap_add
  }
end
