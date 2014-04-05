#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/main'

module Metasm
# this module regroups OS-related functions
# (eg. find_process, inject_shellcode)
# a 'class' just to be able to inherit from it...
class OS
  # represents a running process with a few information, and defines methods to get more interaction (#memory, #debugger)
  class Process
    attr_accessor :pid, :path, :modules
    class Module
      attr_accessor :path, :addr, :size
    end

    def initialize(pid=nil)
      @pid = pid
    end

    def to_s
      mod = File.basename(path) rescue nil
      "#{pid}: ".ljust(6) << (mod || '<unknown>')
    end
    def inspect
      '<Process:' + ["pid: #@pid", modules.to_a.map { |m| " #{'%X' % m.addr} #{m.path}" }].join("\n") + '>'
    end
  end

  # returns the Process whose pid is name (if name is an Integer) or first module path includes name (string)
  def self.find_process(name)
    case name
    when nil
    when Integer
      list_processes.find { |pr| pr.pid == name }
    else
      list_processes.find { |pr| pr.path.to_s.include? name.to_s } or
        (find_process(Integer(name)) if name =~ /^(0x[0-9a-f]+|[0-9]+)$/i)
    end
  end

  # create a new debuggee process stopped at start
  def self.create_process(path)
    dbg = create_debugger(path)
    pr = open_process(dbg.pid)
    pr.debugger = dbg
    pr.memory = dbg.memory
    pr
  end

  # return 'winos' or 'linos' depending on the underlying OS
  def self.shortname
    case RUBY_PLATFORM
    when /mswin|mingw|cygwin/i; 'winos'
    when /linux/i; 'linos'
    end
  end

  # return the platform-specific version
  def self.current
    case shortname
    when 'winos'; WinOS
    when 'linos'; LinOS
    end
  end
end

# This class implements an objects that behaves like a regular string, but
# whose real data is dynamically fetched or generated on demand
# its size is immutable
# implements a page cache
# substrings are Strings (small substring) or another VirtualString
# (a kind of 'window' on the original VString, when the substring length is > 4096)
class VirtualString
  # formats parameters for reading
  def [](from, len=nil)
    if not len and from.kind_of? Range
      b = from.begin
      e = from.end
      b = b + length if b < 0
      e = e + length if e < 0
      len = e - b
      len += 1 if not from.exclude_end?
      from = b
    end
    from = from + length if from < 0

    return nil if from > length or (from == length and not len)
    len = length - from if len and from + len > length
    return '' if len == 0

    read_range(from, len)
  end

  # formats parameters for overwriting portion of the string
  def []=(from, len, val=nil)
    raise TypeError, 'cannot modify frozen virtualstring' if frozen?

    if not val
      val = len
      len = nil
    end
    if not len and from.kind_of? Range
      b = from.begin
      e = from.end
      b = b + length if b < 0
      e = e + length if e < 0
      len = e - b
      len += 1 if not from.exclude_end?
      from = b
    elsif not len
      len = 1
      val = val.chr
    end
    from = from + length if from < 0

    raise IndexError, 'Index out of string' if from > length
    raise IndexError, 'Cannot modify virtualstring length' if val.length != len or from + len > length

    write_range(from, val)
  end

  # returns the full raw data
  def realstring
    ret = ''
    addr = 0
    len = length
    while len > @pagelength
      ret << self[addr, @pagelength]
      addr += @pagelength
      len -= @pagelength
    end
    ret << self[addr, len]
  end

  # alias to realstring
  # for bad people checking respond_to? :to_str (like String#<<)
  # XXX alias does not work (not virtual (a la C++))
  def to_str
    realstring
  end

  # forwards unhandled messages to a frozen realstring
  def method_missing(m, *args, &b)
    if ''.respond_to? m
      puts "Using VirtualString.realstring for #{m} from:", caller if $DEBUG
      realstring.freeze.send(m, *args, &b)
    else
      super(m, *args, &b)
    end
  end

  # avoid triggering realstring from method_missing if possible
  def empty?
    length == 0
  end

  # avoid triggering realstring from method_missing if possible
  # heavily used in to find 0-terminated strings in ExeFormats
  def index(chr, base=0)
    return if base >= length or base <= -length
    if i = self[base, 64].index(chr) or i = self[base, @pagelength].index(chr)
      base + i
    else
      realstring.index(chr, base)
    end
  end

  def rindex(chr, max=length)
    return if max > length
    if max > 64 and i = self[max-64, 64].rindex(chr)
      max - 64 + i
    elsif max > @pagelength and i = self[max-@pagelength, @pagelength].rindex(chr)
      max - @pagelength + i
    else
      realstring.rindex(chr, max)
    end
  end

  # '=~' does not go through method_missing
  def =~(o)
    realstring =~ o
  end

  # implements a read page cache

  # the real address of our first byte
  attr_accessor :addr_start
  # our length
  attr_accessor :length
  # array of [addr, raw data], sorted by first == last accessed
  attr_accessor :pagecache
  # maximum length of self.pagecache (number of cached pages)
  attr_accessor :pagecache_len
  def initialize(addr_start, length)
    @addr_start = addr_start
    @length = length
    @pagecache = []
    @pagecache_len = 4
    @pagelength ||= 4096	# must be (1 << x)
  end

  # returns wether a page is valid or not
  def page_invalid?(addr)
    cache_get_page(@addr_start+addr)[2]
  end

  # invalidates the page cache
  def invalidate
    @pagecache.clear
  end

  # returns the @pagelength-bytes page starting at addr
  # return nil if the page is invalid/inaccessible
  # addr is page-aligned by the caller
  # addr is absolute
  #def get_page(addr, len=@pagelength)
  #end

  # searches the cache for a page containing addr, updates if not found
  def cache_get_page(addr)
    addr &= ~(@pagelength-1)
    i = 0
    @pagecache.each { |c|
      if addr == c[0]
        # most recently used first
        @pagecache.unshift @pagecache.delete_at(i) if i != 0
        return c
      end
      i += 1
    }
    @pagecache.pop if @pagecache.length >= @pagecache_len
    c = [addr]
    p = get_page(addr)
    c << p.to_s.ljust(@pagelength, "\0")
    c << true if not p
    @pagecache.unshift c
    c
  end

  # reads a range from the page cache
  # returns a new VirtualString (using dup) if the request is bigger than @pagelength bytes
  def read_range(from, len)
    from += @addr_start
    if not len
      base, page = cache_get_page(from)
      page[from - base]
    elsif len <= @pagelength
      base, page = cache_get_page(from)
      s = page[from - base, len]
      if from+len-base > @pagelength		# request crosses a page boundary
        base, page = cache_get_page(from+len)
        s << page[0, from+len-base]
      end
      s
    else
      # big request: return a new virtual page
      dup(from, len)
    end
  end

  # rewrites a segment of data
  # the length written is the length of the content (a VirtualString cannot grow/shrink)
  def write_range(from, content)
    invalidate
    rewrite_at(from + @addr_start, content)
  end

  # overwrites a section of the original data
  #def rewrite_at(addr, content)
  #end
end

# on-demand reading of a file
class VirtualFile < VirtualString
  # returns a new VirtualFile of the whole file content (defaults readonly)
  # returns a String if the file is small (<4096o) and readonly access
  def self.read(path, mode='rb')
    raise 'no filename specified' if not path
    if sz = File.size(path) <= 4096 and (mode == 'rb' or mode == 'r')
      File.open(path, mode) { |fd| fd.read }
    else
      File.open(path, mode) { |fd| new fd.dup, 0, sz }
    end
  end

  # the underlying file descriptor
  attr_accessor :fd

  # creates a new virtual mapping of a section of the file
  # the file descriptor must be seekable
  def initialize(fd, addr_start = 0, length = nil)
    @fd = fd
    if not length
      @fd.seek(0, File::SEEK_END)
      length = @fd.tell - addr_start
    end
    super(addr_start, length)
  end

  def dup(addr = @addr_start, len = @length)
    self.class.new(@fd, addr, len)
  end

  # reads an aligned page from the file, at file offset addr
  def get_page(addr, len=@pagelength)
    @fd.pos = addr
    @fd.read len
  end

  def page_invalid?(addr)
    false
  end

  # overwrite a section of the file
  def rewrite_at(addr, data)
    @fd.pos = addr
    @fd.write data
  end

  # returns the full content of the file
  def realstring
    @fd.pos = @addr_start
    @fd.read(@length)
  end
end
end
