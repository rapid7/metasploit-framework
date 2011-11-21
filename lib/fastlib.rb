#!/usr/bin/env ruby

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

module Kernel #:nodoc:all
	alias :fastlib_original_require :require

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

		# TODO: Implement relative path $: checks and adjust the
		#       search path within archives to match.
			
		$:.grep( /^(.*)\.fastlib$/ ).each do |lib|
			data = FastLib.load(lib, name)
			next if not data
			$" << name
			
			# TODO: Implement a better stack trace that represents
			#       the original filename and line number.
			Object.class_eval(data)
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


#
# The FastLib class implements the meat of the FASTLIB archive format
#
class FastLib

	VERSION = "0.0.3"

	@@cache = {}
	
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

		return if not ( @@cache[lib] and @@cache[lib][name] )
		
		
		::File.open(lib, "rb") do |fd|
			fd.seek(
				@@cache[lib][:fastlib_header][0] +
				@@cache[lib][:fastlib_header][1] + 
				@@cache[lib][name][0]
			)
			data = fastlib_filter( fd.read(@@cache[lib][name][1] ))
		end
		
		# Return the contents in raw or processed form
		noprocess ? data : post_process(lib, name, data)
	end
	
	#
	# This method caches the file list and offsets within the archive
	#
	def self.load_cache(lib)
		return if @@cache[lib]
		dict = {}
		::File.open(lib, 'rb') do |fd|
			head = fd.read(4)
			return if head != "FAST"
			hlen = fd.read(4).unpack("N")[0]
			dict[:fastlib_header] = [8, hlen]
			
			nlen, doff, dlen = fd.read(12).unpack("N*")
			
			while nlen > 0
				name = fastlib_filter_name( fd.read(nlen) )
				dict[name] = [doff, dlen]
				
				nlen, doff, dlen = fd.read(12).unpack("N*")
			end
			@@cache[lib] = dict
		end
	end
	
	#
	# This method provides a way to hook the translation of file names
	# from the dictionary in the file to the final string. This can be
	# used to provide encryption or compression.
	#
	def self.fastlib_filter_name(name)
		name
	end

	#
	# This method provides a way to hook the translation of file content
	# from the archive to the final content. This can be used to provide
	# encryption or compression.
	#	
	def self.fastlib_filter(data)
		data
	end

	#
	# This method provides a way to create a FASTLIB archive programatically,
	# the key arguments are the name of the destination archive, the base
	# directory that should be excluded from the archived path, and finally
	# the list of specific files and directories to include in the archive.
	#
	def self.dump(lib, bdir, *dirs)
		head = ""
		data = ""
		hidx = 0
		didx = 0
		
		bdir = bdir.gsub(/\/$/, '')
		brex = /^#{Regexp.escape(bdir)}\//
		
		dirs.each do |dir|
			::Find.find(dir).each do |path|
				next if not ::File.file?(path)
				name = fastlib_filter_name( path.sub( brex, "" ) )
				buff = ""
				::File.open(path, "rb") do |fd|
					buff = fd.read(fd.stat.size)
				end
			
				head << [ name.length, didx, buff.length ].pack("NNN")
				head << name
				hidx = hidx + 12 + name.length
			
				data << fastlib_filter( buff )
				didx = didx + buff.length
			end
		end
		
		head << [0,0,0].pack("NNN")
		
		::File.open(lib, "wb") do |fd|
			fd.write("FAST")
			fd.write( [ head.length ].pack("N") )
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
		( @@cache[lib] || {} ).keys.map{|x| x.to_s }.sort
	end
	
	#
	# This method is called on the loaded is required to expand __FILE__
	# and other inline dynamic constants to map to the correct location.
	#
	def self.post_process(lib, name, data)
		data.gsub('__FILE__', "'#{ ::File.expand_path(::File.join(::File.dirname(lib), name)) }'")
	end
	
end


#
# Allow this library to be used as an executable to create and list
# FASTLIB archives
#
if __FILE__ == $0
	cmd = ARGV.shift
	unless ["dump", "list", "version"].include?(cmd)
		$stderr.puts "Usage: #{$0} [dump|list|version] <arguments>"
		exit(0)
	end
	
	case cmd
	when "dump"
		dst = ARGV.shift
		dir = ARGV.shift
		src = ARGV
		unless dst and dir and src.length > 0
			$stderr.puts "Usage: #{$0} dump destination.fastlib base_dir src1 src2 ... src99"
			exit(0)
		end
		FastLib.dump(dst, dir, *src)
	
	when "list"
		src = ARGV.shift
		unless src
			$stderr.puts "Usage: #{$0} list src_lib "
			exit(0)
		end
		$stdout.puts "Library: #{src}"
		$stdout.puts "====================================================="
		FastLib.list(src).each do |name|
			$stdout.puts " - #{name}"
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
	* The header is always 8 bytes into the archive (magic + header length)
	* The data section is always 8 + header length into the archive
	* The header entries always start with 'fastlib_header'
	* The header entries always consist of 12 bytes + name length (no alignment)
	* The header name data may be encoded, compressed, or transformed
	* The data entries may be encoded, compressed, or transformed too
	

	4 bytes: "FAST"
	4 bytes: NBO header length
	[
		4 bytes: name length (0 = End of Names)
		4 bytes: data offset
		4 bytes: data length
	]
	[ Raw Data ]

=end



