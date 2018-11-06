# -*- coding: binary -*-
#!/usr/bin/env ruby

require 'optparse'
require 'find'

class String
  def to_decimal
    self.unpack("c*").reverse.pack("c*").unpack("N*").first
  end

  def to_hex
    self.unpack("c*").reverse.pack("c*")
  end

  def to_printable_hex_32
    self.unpack("c*").reverse.pack("c*").unpack("H*").first
  end

  def to_printable_hex_64
    self.unpack("s*").pack("s*").reverse.unpack("H*").first
  end

  def unicode
    buf = ''

    self.each_char do |c|
      buf << "#{c}\x00"
    end

    buf
  end

  def ansi
    buf = ''

    self.each_char do |c|
      next if c == "\x00"
      buf << c
    end

    buf
  end
end

class DLLInformation
  X64_86 = :x64_86
  X86    = :x86

  def initialize(file)
    f = open(file, 'rb')
    begin
      @bin = f.read
    ensure
      f.close if f
    end
  end
 
  def cpu_type
    @cpu_type ||= lambda {
      type = @bin.scan(/\x50\x45\x00\x00(..)/).flatten.first || ''
      type == "\x64\x86" ? X64_86 : X86
    }.call
  end

  def base_address
    case cpu_type
    when X64_86
      base_address_x64_86
    when X86
      base_address_x86
    end
  end

  def timestamp
    pe_signature_offset = @bin[60,4].to_decimal
    @bin[pe_signature_offset+8, 4].to_printable_hex_32
  end

  def version_info
    signature_start = "...\x00\x00\x00"
    signature_start << "VS_VERSION_INFO".unicode
    signature_end   = "\x00\x00\x00\x00\x09\x04\xb0\x04"
    info = @bin.scan(/(#{signature_start}.+#{signature_end})/).flatten[0]
    return '' if info.nil?

    signature_start = "FileVersion".unicode
    signature_start << "\x00\x00".unicode
    signature_end   = "InternalName".unicode
    file_version = info.scan(/#{signature_start}(.+)\x00\x00.+#{signature_end}/).flatten[0]
    return '' if file_version.nil?

    file_version
  end

  def size
    @bin.length
  end

  private

  def base_address_x86
    @base_address_x86 ||= lambda {
      pe_signature_offset = @bin[60,4].to_decimal
      coff_header_offset  = pe_signature_offset + 4 + 44 + 4
      @bin[coff_header_offset, 4].to_printable_hex_32
    }.call
  end

  def base_address_x64_86
    @base_address_x64_86 ||= lambda {
      pe_signature_offset =  @bin.index("\x50\x45\x00\x00")
      image_base_offset = pe_signature_offset + 48
      @bin[image_base_offset, 8].to_printable_hex_64
    }.call
  end

end

class Table
  def initialize(opts)
    @path      = opts[:path]
    @size      = opts[:size]
    @version   = opts[:version]
    @base      = opts[:base]
    @timestamp = opts[:timestamp]
  end

  def show
    puts '#{get_size}  #{get_base}  #{get_timestamp}  #{get_version}  #{get_path}'
  end

  private

  def get_size
    s = [@size].pack("V*").unpack("H*")[0]
    "0x#{s.rjust(8, '0')}"
  end

  def get_path
    base = "#{Dir.pwd}/"
    p = @path.gsub(/^#{base}/, '')

    # Max out the length at 44 characters
    p = "#{p[0,44]}..." if p.length > 44

    p
  end

  def get_version
    @version.ansi.scan(/^([0-9\.]+) /).flatten.first.ljust(16, ' ')
  end

  def get_base
    "0x#{@base.ljust(16, ' ')}"
  end

  def get_timestamp
    "0x#{@timestamp.rjust(8, '0')}"
  end
end

def init_args
  opts = {}
  opt = OptionParser.new
  opt.banner = "Usage: #{__FILE__} [options]"
  opt.separator('')
  opt.separator('Options:')

  opt.on('-d', '--dll [string]', String, 'DLL to specify') do |n|
    opts[:dll_name] = n
  end

  opt.on_tail('-h', '--help', 'Show usage') do
    puts opt
    exit(0)
  end

  opt.parse!
  opts
end

def list_dll(dir, dll_name)
  puts 'Size        Base                Timestamp   Version           Path'

  Find.find(dir) do |p|
    next if p !~ /\.dll$/i
    next if dll_name && p !~ /#{dll_name}/

    dll = DLLInformation.new(p)
    size         = dll.size
    version      = dll.version_info
    base_address = dll.base_address
    timestamp    = dll.timestamp

    t = Table.new({
      :path      => p,
      :size      => size,
      :version   => version,
      :base      => base_address,
      :timestamp => timestamp
    })

    t.show
  end
end

def main(args)
  base_dir = Dir.pwd
  list_dll(base_dir, args[:dll_name])
end

args = init_args
begin
  main(args)
rescue RuntimeError => e
  puts e.message
  exit(0)
rescue Interrupt
end
