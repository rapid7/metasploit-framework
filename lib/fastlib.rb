#!/usr/bin/env ruby
# -*- coding: binary -*-

#
# FASTLIB is a mechanism for loading large sets of libraries in a way that is
# faster and much more flexible than typical disk structures. FASTLIB includes
# hooks that can be used for both compression and encoding of Ruby libraries.
#

#
# This format was specifically created to improve the performance and
# AV-resistance of the Metasploit Framework and Rex libraries.
#


#
# This library is still in its early form; a large number of performance and
# compatiblity improvements are not yet included. Do not depend on the FASTLIB
# file format at this time.
#

require "find"


#
# Copyright (C) 2011 Rapid7. You can redistribute it and/or
# modify it under the terms of the ruby license.
#
#
# Roughly based on the rubyzip zip/ziprequire library:
# 	>> Copyright (C) 2002 Thomas Sondergaard
# 	>> rubyzip is free software; you can redistribute it and/or
# 	>> modify it under the terms of the ruby license.


#
# The FastLib class implements the meat of the FASTLIB archive format
#
class FastLib

  VERSION = "0.0.8"

  FLAG_COMPRESS = 0x01
  FLAG_ENCRYPT  = 0x02

  @@cache = {}
  @@has_zlib = false

  #
  # Load zlib support if possible
  #
  begin
    require 'zlib'
    @@has_zlib = true
  rescue ::LoadError
  end

  #
  # This method returns the version of the fastlib library
  #
  def self.version
    VERSION
  end

  #
  # This method loads content from a specific archive file by name. If the
  # noprocess argument is set to true, the contents will not be expanded to
  # include workarounds for things such as __FILE__. This is useful when
  # loading raw binary data where these strings may occur
  #
  def self.load(lib, name, noprocess=false)
    data = ""
    load_cache(lib)

    return unless ( @@cache[lib] and @@cache[lib][name] )


    ::File.open(lib, "rb") do |fd|
      fd.seek(
        @@cache[lib][:fastlib_header][0] +
        @@cache[lib][:fastlib_header][1] +
        @@cache[lib][name][0]
      )
      data = fastlib_filter_decode( lib, fd.read(@@cache[lib][name][1] ))
    end

    # Return the contents in raw or processed form
    noprocess ? data : post_process(lib, name, data)
  end

  #
  # This method caches the file list and offsets within the archive
  #
  def self.load_cache(lib)
    return if @@cache[lib]
    @@cache[lib] = {}

    return if not ::File.exists?(lib)

    ::File.open(lib, 'rb') do |fd|
      dict = {}
      head = fd.read(4)
      return if head != "FAST"
      hlen = fd.read(4).unpack("N")[0]
      flag = fd.read(4).unpack("N")[0]

      @@cache[lib][:fastlib_header] = [12, hlen, fd.stat.mtime.utc.to_i ]
      @@cache[lib][:fastlib_flags]  = flag

      nlen, doff, dlen, tims = fd.read(16).unpack("N*")

      while nlen > 0
        name = fastlib_filter_decode( lib, fd.read(nlen) )
        dict[name] = [doff, dlen, tims]

        nlen, doff, dlen, tims = fd.read(16).unpack("N*")
      end

      @@cache[lib].merge!(dict)
    end

  end

  #
  # This method provides compression and encryption capabilities
  # for the fastlib archive format.
  #
  def self.fastlib_filter_decode(lib, buff)

    if (@@cache[lib][:fastlib_flags] & FLAG_ENCRYPT) != 0

      @@cache[lib][:fastlib_decrypt] ||= ::Proc.new do |data|
        stub = "decrypt_%.8x" % ( @@cache[lib][:fastlib_flags] & 0xfffffff0 )
        FastLib.send(stub, data)
      end

      buff = @@cache[lib][:fastlib_decrypt].call( buff )
    end

    if (@@cache[lib][:fastlib_flags] & FLAG_COMPRESS) != 0
      if not @@has_zlib
        raise ::RuntimeError, "zlib is required to open this archive"
      end

      z = Zlib::Inflate.new
      buff = z.inflate(buff)
      buff << z.finish
      z.close
    end

    buff
  end

  #
  # This method provides compression and encryption capabilities
  # for the fastlib archive format.
  #
  def self.fastlib_filter_encode(lib, buff)

    if (@@cache[lib][:fastlib_flags] & FLAG_COMPRESS) != 0
      if not @@has_zlib
        raise ::RuntimeError, "zlib is required to open this archive"
      end

      z = Zlib::Deflate.new
      buff = z.deflate(buff)
      buff << z.finish
      z.close
    end

    if (@@cache[lib][:fastlib_flags] & FLAG_ENCRYPT) != 0

      @@cache[lib][:fastlib_encrypt] ||= ::Proc.new do |data|
        stub = "encrypt_%.8x" % ( @@cache[lib][:fastlib_flags] & 0xfffffff0 )
        FastLib.send(stub, data)
      end

      buff = @@cache[lib][:fastlib_encrypt].call( buff )
    end

    buff
  end


  # This method provides a way to create a FASTLIB archive programatically.
  #
  # @param [String] lib the output path for the archive
  # @param [String] flag a string containing the hex values for the
  #   flags ({FLAG_COMPRESS} and {FLAG_ENCRYPT}).
  # @param [String] bdir the path to the base directory which will be
  #   stripped from all paths included in the archive
  # @param [Array<String>] dirs list of directories/files to pack into
  #   the archive.  All dirs should be under bdir so that the paths are
  #   stripped correctly.
  # @return [void]
  def self.dump(lib, flag, bdir, *dirs)
    head = ""
    data = ""
    hidx = 0
    didx = 0

    bdir = bdir.gsub(/\/$/, '')
    brex = /^#{Regexp.escape(bdir)}\//

    @@cache[lib] = {
      :fastlib_flags => flag.to_i(16)
    }

    dirs.each do |dir|
      ::Find.find(dir) do |path|
        next if not ::File.file?(path)
        name = fastlib_filter_encode( lib, path.sub( brex, "" ) )

        buff = ""
        ::File.open(path, "rb") do |fd|
          buff = fastlib_filter_encode(lib, fd.read(fd.stat.size))
        end


        head << [ name.length, didx, buff.length, ::File.stat(path).mtime.utc.to_i ].pack("NNNN")
        head << name
        hidx = hidx + 16 + name.length

        data << buff
        didx = didx + buff.length
      end
    end

    head << [0,0,0].pack("NNN")

    ::File.open(lib, "wb") do |fd|
      fd.write("FAST")
      fd.write( [ head.length, flag.to_i(16) ].pack("NN") )
      fd.write( head )
      fd.write( data )
    end
  end

  #
  # This archive provides a way to list the contents of an archive
  # file, returning the names only in sorted order.
  #
  def self.list(lib)
    load_cache(lib)
    ( @@cache[lib] || {} ).keys.map{|x| x.to_s }.sort.select{ |x| @@cache[lib][x] }
  end

  #
  # This method is called on the loaded is required to expand __FILE__
  # and other inline dynamic constants to map to the correct location.
  #
  def self.post_process(lib, name, data)
    data.gsub('__FILE__', "'#{ ::File.expand_path(::File.join(::File.dirname(lib), name)) }'")
  end

  #
  # This is a stub crypto handler that performs a basic XOR
  # operation against a fixed one byte key. The two usable IDs
  # are 12345600 and 00000000
  #
  def self.encrypt_12345600(data)
    encrypt_00000000(data)
  end

  def self.decrypt_12345600(data)
    encrypt_00000000(data)
  end

  def self.encrypt_00000000(data)
    data.unpack("C*").map{ |c| c ^ 0x90 }.pack("C*")
  end

  def self.decrypt_00000000(data)
    encrypt_00000000(data)
  end

  #
  # Expose the cache to callers
  #
  def self.cache
    @@cache
  end
end


#
# Allow this library to be used as an executable to create and list
# FASTLIB archives
#
if __FILE__ == $0
  cmd = ARGV.shift
  unless ["store", "list", "version"].include?(cmd)
    $stderr.puts "Usage: #{$0} [dump|list|version] <arguments>"
    exit(0)
  end

  case cmd
  when "store"
    dst = ARGV.shift
    flg = ARGV.shift
    dir = ARGV.shift
    src = ARGV
    unless dst and dir and src.length > 0
      $stderr.puts "Usage: #{$0} store destination.fastlib flags base_dir src1 src2 ... src99"
      exit(0)
    end
    FastLib.dump(dst, flg, dir, *src)

  when "list"
    src = ARGV.shift
    unless src
      $stderr.puts "Usage: #{$0} list"
      exit(0)
    end
    $stdout.puts "Library: #{src}"
    $stdout.puts "====================================================="
    FastLib.list(src).each do |name|
      fsize = FastLib.cache[src][name][1]
      ftime = ::Time.at(FastLib.cache[src][name][2]).strftime("%Y-%m-%d %H:%M:%S")
      $stdout.puts sprintf("%9d\t%20s\t%s\n", fsize, ftime, name)
    end
    $stdout.puts ""

  when "version"
    $stdout.puts "FastLib Version #{FastLib.version}"
  end

  exit(0)
end

#
# FASTLIB archive format (subject to change without notice)
#
=begin

  * All integers are 32-bit and in network byte order (big endian / BE)
  * The file signature is 0x46415354 (big endian, use htonl() if necessary)
  * The header is always 12 bytes into the archive (magic + header length)
  * The data section is always 12 + header length into the archive
  * The header entries always start with 'fastlib_header'
  * The header entries always consist of 16 bytes + name length (no alignment)
  * The header name data may be encoded, compressed, or transformed
  * The data entries may be encoded, compressed, or transformed too


  4 bytes: "FAST"
  4 bytes: NBO header length
  4 bytes: NBO flags (24-bit crypto ID, 8 bit modes)
  [
    4 bytes: name length (0 = End of Names)
    4 bytes: data offset
    4 bytes: data length
    4 bytes: timestamp
  ]
  [ Raw Data ]

=end


module Kernel #:nodoc:all
  alias :fastlib_original_require :require

  #
  # Store the CWD when were initially loaded
  # required for resolving relative paths
  #
  @@fastlib_base_cwd = ::Dir.pwd

  #
  # This method hooks the original Kernel.require to support
  # loading files within FASTLIB archives
  #
  def require(name)
    fastlib_require(name) || fastlib_original_require(name)
  end

  #
  # This method handles the loading of FASTLIB archives
  #
  def fastlib_require(name)
    name = name + ".rb" if not name =~ /\.rb$/
    return false if fastlib_already_loaded?(name)
    return false if fastlib_already_tried?(name)

    # XXX Implement relative search paths within archives
    $:.map{ |path|
      (path =~ /^([A-Za-z]\:|\/)/ ) ? path : ::File.expand_path( ::File.join(@@fastlib_base_cwd, path) )
    }.map{  |path| ::Dir["#{path}/*.fastlib"] }.flatten.uniq.each do |lib|
      data = FastLib.load(lib, name)
      next if not data
      $" << name

      Object.class_eval(data, lib + "::" + name)

      return true
    end

    $fastlib_miss << name

    false
  end

  #
  # This method determines whether the specific file name
  # has already been loaded ($LOADED_FEATURES aka $")
  #
  def fastlib_already_loaded?(name)
    re = Regexp.new("^" + Regexp.escape(name) + "$")
    $".detect { |e| e =~ re } != nil
  end

  #
  # This method determines whether the specific file name
  # has already been attempted with the included FASTLIB
  # archives.
  #
  # TODO: Ensure that this only applies to known FASTLIB
  #       archives and that newly included archives will
  #       be searched appropriately.
  #
  def fastlib_already_tried?(name)
    $fastlib_miss ||= []
    $fastlib_miss.include?(name)
  end
end




