#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


module Metasm
class Heap
  attr_accessor :vm, :range, :ptsz
  attr_accessor :cp
  # hash chunk userdata pointer -> chunk userdata size
  attr_accessor :chunks
  # hash chunk user pointer -> C::Struct
  attr_accessor :chunk_struct
  # the chunk graph: chunk pointer -> [array of chunks addrs pointed]
  attr_accessor :xrchunksto, :xrchunksfrom

  def initialize(dbg)
    @dbg = dbg
    @dbg.pid_stuff_list << :heap
    @dbg.heap = self
    @range = {}
    @dwcache = {}
    # userdata_ptr => len
    @chunks = {}
    @xrchunksto = {}
    @xrchunksfrom = {}
    @ptsz = dbg.cpu.size/8
    # ptr => C::Struct
    @chunk_struct = {}
  end

  def pagecache(base, len)
    @dbg.read_mapped_range(base, len)
  end

  def dwcache(base, len)
    @dwcache[[base, len]] ||= pagecache(base, len).unpack(@ptsz == 4 ? 'L*' : 'Q*')
  end

  # return the array of dwords in the chunk
  def chunkdw(ptr, len=@chunks[ptr])
    if base = find_range(ptr)
      dwcache(base, @range[base])[(ptr-base)/@ptsz, len/@ptsz]
    end
  end

  # returns the list of chunks, sorted
  def chunklist
    @chunklist ||= @chunks.keys.sort
  end

  # dichotomic search of the chunk containing ptr
  # len = hash ptr => length
  # list = list of hash keys sorted
  def find_elem(ptr, len, list=nil)
    return ptr if len[ptr]

    list ||= len.keys.sort

    if list.length < 16
      return list.find { |p| p <= ptr and p + len[p] > ptr }
    end 

    window = list
    while window and not window.empty?
      i = window.length/2
      wi = window[i]
      if ptr < wi
        window = window[0, i]
      elsif ptr < wi + len[wi]
        return wi
      else
        window = window[i+1, i]
      end
    end
  end

  # find the chunk encompassing ptr
  def find_chunk(ptr)
    find_elem(ptr, @chunks, chunklist)
  end

  def find_range(ptr)
    @range_keys ||= @range.keys.sort
    find_elem(ptr, @range, @range_keys)
  end

  # { chunk size => [list of chunk addrs] }
  attr_accessor :buckets
  def bucketize
    @buckets = {}
    chunklist.each { |a|
      (@buckets[@chunks[a]] ||= []) << a
    }
  end

  # find the kernels of the graph (strongly connected components)
  # must be called after scan_xr
  # also find the graph diameter
  attr_accessor :kernels, :maxpath
  def find_kernels(adj = @xrchunksto)
    @maxpath = []
    kernels = {}
    adj.keys.sort.each { |ptr|
      next if kernels[ptr]
      paths = [[ptr]]
      while path = paths.pop
        next if not l = @xrchunksfrom[path.first]
        l.each { |pl|
          next if kernels[pl]
          next if not adj[pl]
          if path.include?(pl)
            kernels[pl] = true
          else
            paths << [pl, *path]
          end
        }
        @maxpath = paths.last if paths.last and paths.last.length > @maxpath.length
      end
    }
    if @maxpath.first and np = (adj[@maxpath.last] - @maxpath).first
      @maxpath << np
    end
    @kernels = []
    while k = kernels.index(true)
      curk = reachfrom(k, adj).find_all { |ok|
        true == reachfrom(ok, adj) { |tk|
          break true if tk == k
        }
      }
      @kernels << curk
      curk.each { |ka| kernels.delete ka }
    end
  end

  attr_accessor :roots
  # find the root nodes that allow acces to most other nodes
  # { root => [reachable nodes] }
  # does not include single nodes (@chunks.keys - @xrchunksfrom.keys)
  def find_roots(adj=@xrchunksto)
    @roots = {}
    adj.keys.sort.each { |r|
      if not @roots[r]
        l = reachfrom(r, adj, @roots)
        l.each { |t| @roots[t] = true if adj[t] }	# may include r !, also dont mark leaves
        @roots[r] = l
      end
    }
    @roots.delete_if { |k, v| v == true }
  end

  def reachfrom(p, adj = @xrchunksto, roots={})
    return roots[p] if roots[p].kind_of? Array
    hash = {}
    todo = [p]
    while p = todo.pop
      if to = roots[p] || adj[p] and to.kind_of? Array
        to.each { |tk|
          if not hash[tk]
            hash[tk] = true
            todo << tk
            yield tk if block_given?
          end
        }
      end
    end
    hash.keys
  end

  # create a subset of xrchunksto from one point
  def graph_from(p, adj = @xrchunksto)
    hash = {}
    todo = [p]
    while p = todo.pop
      next if hash[p]
      if adj[p]
        hash[p] = adj[p]
        todo.concat hash[p]
      end
    end
    hash
  end

  # dump the whole graph in a dot file
  def dump_graph(fname='graph.gv', graph=@xrchunksto)
    File.open(fname, 'w') { |fd|
      fd.puts "digraph foo {"
      graph.each { |b, l|
        fd.puts l.map { |e| '"%x" -> "%x";' % [b, e] }
      }
      fd.puts "}"
    }
  end

  # chunk ptr => { dwindex => [list of ptrs] }
  attr_accessor :linkedlists, :alllists
  def find_linkedlists
    @linkedlists = {}
    @alllists = []
    @buckets.sort.each { |sz, lst|
      #puts "sz #{sz} #{lst.length}"
      lst.each { |ptr|
        next if not l = @xrchunksto[ptr]
        next if not l.find { |tg| @chunks[tg] == sz }
        dw = chunkdw(ptr)
        dw.length.times { |dwoff|
          next if @linkedlists[ptr] and @linkedlists[ptr][dwoff]
          tg = dw[dwoff]
          next if @chunks[tg] != sz
          check_linkedlist(ptr, dwoff)
        }
      }
    }
  end

  def check_linkedlist(ptr, dwoff)
    psz = @chunks[ptr]
    fwd = ptr
    lst = [fwd]
    base = find_range(fwd)
    loop do
      if not base or base > fwd or base + @range[base] <= fwd
        base = find_range(fwd)
      end
      break if not base
      fwd = dwcache(base, @range[base])[(fwd-base)/@ptsz + dwoff]
      break if fwd == 0
      return if not cl = @chunks[fwd] # XXX root/tail may be in .data
      return if cl != psz
      break if lst.include? fwd
      lst << fwd
    end
    fwd = ptr
    while pv = @xrchunksfrom[fwd]
      fwd = pv.find { |p|
        next if @chunks[p] != psz
        if not base or base > p or base + @range[base] <= p
          base = find_range(fwd)
        end
        dwcache(base, @range[base])[(p-base)/@ptsz + dwoff] == fwd
      }
      break if not fwd
      break if lst.include? fwd
      lst.unshift fwd
    end
    if lst.length > 3
      lst.each { |p| (@linkedlists[p] ||= {})[dwoff] = lst }
      @alllists << lst
    end
  end

  # { chunkinarray => { rootptr => [chunks] } }
  attr_accessor :arrays, :allarrays
  def find_arrays
    @arrays = {}
    @allarrays = []
    @buckets.sort.each { |sz, lst|
      next if sz < @ptsz*6
      lst.each { |ptr|
        next if not to = @xrchunksto[ptr]
        # a table must have at least half its storage space filled with ptrs
        next if to.length <= sz/@ptsz/2
        # also, ptrs must point to same-size stuff
        lsz = Hash.new(0)
        to.each { |t| lsz[@chunks[t]] += 1 }
        cnt = lsz.values.max
        next if cnt <= sz/@ptsz/2
        tgsz = lsz.index(cnt)
        ar = to.find_all { |t| @chunks[t] == tgsz }.uniq
        next if ar.length <= sz/@ptsz/2
        ar.each { |p| (@arrays[p] ||= {})[ptr] = ar }
        @allarrays << ar
      }
    }
  end
end

class LinuxHeap < Heap
  # find all chunks in the memory address space
  attr_accessor :mmaps

  def scan_chunks
    @chunks = {}
    each_heap { |a, l, ar|
      scan_heap(a, l, ar)
    }
    @mmapchunks = []
    @mmaps.each { |a, l|
      ll = scan_mmap(a, l) || 4096
      a += ll
      l -= ll
    }
  end

  # scan all chunks for cross-references (one chunk contaning a pointer to some other chunk)
  def scan_chunks_xr
    @xrchunksto = {}
    @xrchunksfrom = {}
    each_heap { |a, l, ar|
      scan_heap_xr(a, l)
    }
    @mmapchunks.each { |a|
      scan_mmap_xr(a, @chunks[a])
    }
  end

  # scan chunks from a heap base addr
  def scan_heap(base, len, ar)
    dw = dwcache(base, len)
    ptr = 0

    psz = dw[ptr]
    sz = dw[ptr+1]
    base += 2*@ptsz	# user pointer
    raise "bad heap base %x %x  %x %x" % [psz, sz, base, len] if psz != 0 or sz & 1 == 0

    loop do
      clen = sz & -8	# chunk size
      ptr += clen/@ptsz	# start of next chk
      break if ptr >= dw.length or clen == 0
      sz = dw[ptr+1]
      if sz & 1 > 0	# pv_inuse
        # user data length up to chucksize-4 (over next psz)
        #puts "used #{'%x' % base} #{clen-@ptsz}" if $VERBOSE
        @chunks[base] = clen-@ptsz
      else
        #puts "free #{'%x' % base} #{clen-@ptsz}" if $VERBOSE
      end
      base += clen
    end

    del_fastbin(ar)
  end

  def scan_heap_xr(base, len)
    dw = dwcache(base, len)
    @chunks.each_key { |p|
      i = (p-base) / @ptsz
      if i >= 0 and i < dw.length
        lst = dw[i, @chunks[p]/@ptsz].find_all { |pp| @chunks[pp] }
        @xrchunksto[p] = lst if not lst.empty?
        lst.each { |pp| (@xrchunksfrom[pp] ||= []) << p }
      end
    }
  end

  # scan chunks from a mmap base addr
  # big chunks are allocated on anonymous-mmap areas
  # for mmap chunks, pv_sz=0 pv_inuse=0, mmap=1, data starts at 8, mmapsz = userlen+12 [roundup 4096]
  # one entry in /proc/pid/maps may point to multiple consecutive mmap chunks
  # scans for a mmap chunk header, returns the chunk size if pattern match or nil
  def scan_mmap(base, len)
    foo = chunkdata(base)
    clen = foo[1] & ~0xfff
    if foo[0] == 0 and foo[1] & 0xfff == 2 and clen > 0 and clen <= len
      @chunks[base + foo.length] = clen-4*@ptsz
      @mmapchunks << (base + foo.length)
      clen
    end
  end

  def scan_mmap_xr(base, len)
    dw = dwcache(base, len)
    lst = dw[2..-1].find_all { |pp| @chunks[pp] }
    @xrchunksto[base] = lst if not lst.empty?
    lst.each { |pp| (@xrchunksfrom[pp] ||= []) << base }
  end

  attr_accessor :main_arena_ptr

  # we need to find the main_arena from the libc
  # we do this by analysing 'malloc_trim'
  def scan_libc(addr)
    raise 'no libc' if not addr

    return if @main_arena_ptr = @dbg.symbols.index('main_arena')

    unless trim = @dbg.symbols.index('malloc_trim') || @dbg.symbols.index('weak_malloc_trim')
      @dbg.loadsyms 'libc[.-]'
      trim = @dbg.symbols.index('malloc_trim') || @dbg.symbols.index('weak_malloc_trim')
    end
    raise 'cant find malloc_trim' if not trim

    d = @dbg.disassembler

    d.disassemble_fast(trim) if not d.di_at(trim)
    if d.block_at(trim).list.last.opcode.name == 'call'
      # x86 getip, need to dasm to have func_binding (cross fingers)
      d.disassemble d.block_at(trim).to_normal.first
    end
    d.each_function_block(trim) { |b|
      # mutex_lock(&main_arena.mutex) gives us the addr
      next if not cmpxchg = d.block_at(b).list.find { |di| di.kind_of? DecodedInstruction and di.opcode.name == 'cmpxchg' }
      @main_arena_ptr = d.backtrace(cmpxchg.instruction.args.first.symbolic.pointer, cmpxchg.address)
      if @main_arena_ptr.length == 1
        @main_arena_ptr = @main_arena_ptr[0].reduce
        break
      end
    }
    raise "cant find mainarena" if not @main_arena_ptr.kind_of? Integer
    @dbg.symbols[@main_arena_ptr] = 'main_arena'
  end

  def chunkdata(ptr)
    @cp.decode_c_ary('uintptr_t', 2, @dbg.memory, ptr).to_array
  end

  def each_heap
    if not @cp.toplevel.struct['malloc_state']
      @cp.parse <<EOS
// TODO autotune these 2 defines..
#define THREAD_STATS 0
//#define PER_THREAD

#define NFASTBINS 10
#define NBINS 128
#define BINMAPSIZE (NBINS/32)

struct malloc_state {
  int mutex;
  int flags;
#if THREAD_STATS
  long stat_lock_direct, stat_lock_loop, stat_lock_wait;
#endif
  void *fastbinsY[NFASTBINS];
  void *top;
  void *last_remainder;
  void *bins[NBINS * 2 - 2];	// *2: double-linked list
  unsigned int binmap[BINMAPSIZE];
  struct malloc_state *next;
#ifdef PER_THREAD
  struct malloc_state *next_free;
#endif
  uintptr_t system_mem;	// XXX int32?
  uintptr_t max_system_mem;
};

struct heap_info {
  struct malloc_state *ar_ptr; // Arena for this heap.
  struct _heap_info *prev; // Previous heap.
  uintptr_t size;   // Current size in bytes. XXX int32?
  uintptr_t mprotect_size; // Size in bytes that has been mprotected
};
EOS
    end

    ptr = @main_arena_ptr
    loop do
      ar = @cp.decode_c_struct('malloc_state', @dbg.memory, ptr)
      if ptr == @main_arena_ptr
        # main arena: find start from top.end - system_mem
        toplen = chunkdata(ar.top)[1] & -8
        yield ar.top + toplen - ar.system_mem, ar.system_mem, ar
      else
        # non-main arena: find heap_info for top, follow list
        iptr = ar.top & -0x10_0000	# XXX
        while iptr
          hi = @cp.decode_c_struct('heap_info', @dbg.memory, iptr)
          off = hi.sizeof
          off += ar.sizeof if iptr+off == hi.ar_ptr
          yield iptr+off, hi.size-off, ar

          iptr = hi.prev
        end
      end

      ptr = ar.next
      break if ptr == @main_arena_ptr
    end
  end

  def del_fastbin(ar)
    nfastbins = 10
    nfastbins.times { |i|
      ptr = ar.fastbinsy[i]
      while ptr
        @chunks.delete ptr+2*@ptsz
        ptr = @cp.decode_c_ary('void *', 3, @dbg.memory, ptr)[2]
      end
    }
  end
end


class WindowsHeap < Heap
  attr_accessor :heaps

  def scan_chunks
    @hsz = @cp.sizeof(@cp.find_c_struct('_HEAP_ENTRY'))
    @chunks = {}
    each_heap { |ar| scan_heap(ar) }
  end

  # scan all chunks for cross-references (one chunk containing a pointer to some other chunk)
  def scan_chunks_xr
    @xrchunksto = {}
    @xrchunksfrom = {}
    each_heap { |ar| scan_heap_xr(ar) }
  end

  # scan chunks from a heap
  def scan_heap(ar)
    each_heap_segment(ar) { |p, l|
      scan_heap_segment(p, l)
    }
    scan_frontend(ar)
    scan_valloc(ar)
  end

  def scan_frontend(ar)
    if ar.frontendheaptype == 1
      laptr = ar.frontendheap
      @chunks.delete laptr	# not a real (user) chunk
      128.times {
        la = @cp.decode_c_struct('_HEAP_LOOKASIDE', @dbg.memory, laptr)
        free = la.listhead.flink
        while free
          @chunks.delete free
          free = @cp.decode_c_struct('_LIST_ENTRY', @dbg.memory, free).flink
        end
        laptr += la.sizeof
      }
    end
  end

  def scan_valloc(ar)
    each_listentry(ar.virtualallocdblocks, '_HEAP_VIRTUAL_ALLOC_ENTRY') { |va|
      # Unusedbyte count stored in the BusyBlock.Size field
      @chunks[va.stroff + va.sizeof] = va.CommitSize - va.Size
    }
  end

  def scan_heap_segment(first, len)
    off = 0
    heapcpy = pagecache(first, len)
    while off < len
      he = @cp.decode_c_struct('_HEAP_ENTRY', heapcpy, off)
      sz = he.Size*8
      if he.Flags & 1 == 1
        @chunks[first+off+@hsz] = sz - he.UnusedBytes
      end
      off += sz
    end
  end

  def scan_heap_xr(ar)
    each_heap_segment(ar) { |p, l|
      scan_heap_segment_xr(p, l)
    }
  end

  def scan_heap_segment_xr(first, len)
    off = 0
    heapcpy = pagecache(first, len)
    while off < len
      he = @cp.decode_c_struct('_HEAP_ENTRY', heapcpy, off)
      sz = he.Size*8
      ptr = first + off + @hsz
      if he.Flags & 1 == 1 and csz = @chunks[ptr] and csz > 0
        heapcpy[off + @hsz, csz].unpack('L*').each { |p|
          if @chunks[p]
            (@xrchunksto[ptr] ||= []) << p
            (@xrchunksfrom[p] ||= []) << ptr
          end
        }
      end
      off += sz
    end
  end

  # yields the _HEAP structure for all heaps
  def each_heap
    heaps.each { |a, l|
      ar = @cp.decode_c_struct('_HEAP', @dbg.memory, a)
      yield ar
    }
  end

  # yields all [ptr, len] for allocated segments of a _HEAP
  # this maps to the _HEAP_SEGMENT further subdivised to skip
  # the _HEAP_UNCOMMMTTED_RANGE areas
  # for the last chunk of the _HEAP_SEGMENT, only yield up to chunk_header
  def each_heap_segment(ar)
    ar.segments.to_array.compact.each { |a|
      sg = @cp.decode_c_struct('_HEAP_SEGMENT', @dbg.memory, a)
      skiplist = []
      ptr = sg.uncommittedranges
      while ptr
        ucr = @cp.decode_c_struct('_HEAP_UNCOMMMTTED_RANGE', @dbg.memory, ptr)
        skiplist << [ucr.Address, ucr.Size]
        ptr = ucr.Next
      end
      ptr = sg.firstentry
      # XXX lastentryinsegment == firstentry ???
      # lastvalidentry = address of the end of the segment (may point to unmapped space)
      ptrend = sg.lastvalidentry
      skiplist.delete_if { |sa, sl| sa < ptr or sa + sl > ptrend }
      skiplist << [ptrend, 1]
      skiplist.sort.each { |sa, sl|
        yield(ptr, sa-ptr)
        ptr = sa + sl
      }
    }
  end

  # call with a LIST_ENTRY allocstruct, the target structure and LE offset in this structure
  def each_listentry(le, st, off=0)
    ptr0 = le.stroff
    ptr = le.flink
    while ptr != ptr0
      yield @cp.decode_c_struct(st, @dbg.memory, ptr-off)
      ptr = @cp.decode_c_struct('_LIST_ENTRY', @dbg.memory, ptr).flink
    end
  end
end

class Windows7Heap < WindowsHeap
  # 4-byte xor key to decrypt the chunk headers
  attr_accessor :chunkkey_size, :chunkkey_flags, :chunkkey_unusedbytes
  def each_heap_segment(ar)
    if ar.encodeflagmask != 0
      @chunkkey_size = ar.encoding.size
      @chunkkey_flags = ar.encoding.flags
      @chunkkey_unusedbytes = ar.encoding.unusedbytes
    else
      @chunkkey_size = 0
      @chunkkey_flags = 0
      @chunkkey_unusedbytes = 0
    end

    each_listentry(ar.segmentlist, '_HEAP_SEGMENT', 0x10) { |sg|
      skiplist = []
      each_listentry(sg.ucrsegmentlist, '_HEAP_UCR_DESCRIPTOR', 8) { |ucr|
        skiplist << [ucr.address, ucr.size]
      }

      ptr = sg.firstentry
      ptrend = sg.lastvalidentry + @hsz
      skiplist.delete_if { |sa, sl| sa < ptr or sa + sl > ptrend }
      skiplist << [ptrend, 1]
      skiplist.sort.each { |sa, sl|
        yield(ptr, sa-ptr)
        ptr = sa + sl
      }
    }
  end

  def scan_heap_segment(first, len)
    off = 0
    heapcpy = pagecache(first, len)
    while off < len
      he = @cp.decode_c_struct('_HEAP_ENTRY', heapcpy, off)
      sz = (he.Size ^ @chunkkey_size)*8
      if (he.Flags ^ @chunkkey_flags) & 1 == 1
        @chunks[first+off+@hsz] = sz - (he.UnusedBytes ^ @chunkkey_unusedbytes)
      end
      off += sz
    end
  end

  def scan_frontend(ar)
    return if ar.frontendheaptype != 2
    lfh = @cp.decode_c_struct('_LFH_HEAP', @dbg.memory, ar.frontendheap)
    lfh.localdata[0].segmentinfo.to_array.each { |sinfo|
      sinfo.cacheditems.to_array.each { |ssp|
        next if not ssp
        subseg = @cp.decode_c_struct('_HEAP_SUBSEGMENT', @dbg.memory, ssp)
        scan_lfh_ss(subseg)
      }
    }
  end

  def scan_lfh_ss(subseg)
    up = subseg.userblocks
    return if not up
    bs = subseg.blocksize
    bc = subseg.blockcount
    list = Array.new(bc) { |i| up + 0x10 + bs*8*i }

    free = []
    ptr = subseg.freeentryoffset
    subseg.depth.times { 
      free << (up + 8*ptr)
      ptr = @dbg.memory[up + 8*ptr + 8, 2].unpack('v')[0]
    }
@foo ||= 0
@foo += 1
p @foo if @foo % 10 == 0

    up += 0x10
    list -= free
    list.each { |p| @chunks[p+8] = bs*8 - (@cp.decode_c_struct('_HEAP_ENTRY', @dbg.memory, p).unusedbytes & 0x7f) }
  end

  def scan_chunks_xr
    @xrchunksto = {}
    @xrchunksfrom = {}
    @chunks.each { |a, l|
      pagecache(a, l).unpack('L*').each { |p|
        if @chunks[p]
          (@xrchunksto[a] ||= []) << p
          (@xrchunksfrom[p] ||= []) << a
        end
      }
    }
  end
end
end
