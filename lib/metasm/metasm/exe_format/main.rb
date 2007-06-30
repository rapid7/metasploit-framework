#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'
require 'metasm/parse'
require 'metasm/encode'
require 'metasm/decode'

module Metasm
class ExeFormat
	attr_accessor :cpu, :encoded

	# creates a new instance, populates self.encoded with the supplied string
	def self.load(str, *a)
		e = new(*a)
		e.encoded << str
		e
	end

	# same as +load+, but from a file
	# uses VirtualFile if available
	def self.load_file(path, *a)
		if defined? VirtualFile
			load(VirtualFile.read(path), *a)
		else
			File.open(path, 'rb') { |fd| load(fd.read, *a) }
		end
	end

	# +load_file+ then decode
	def self.decode_file(path, *a)
		e = load_file(path, *a)
		e.decode
		e
	end

	# +load_file+ then decode header
	def self.decode_file_header(path, *a)
		e = load_file(path, *a)
		e.decode_header
		e
	end

	# creates a new object using the specified cpu, parses the asm source, and assemble
	def self.assemble(cpu, source)
		ex = new(cpu)
		caller.first =~ /^(.*?):(\d+)/
		ex.parse(source, $1, $2.to_i+1)
		ex.assemble
		ex
	end

	# encodes the executable as a string, checks that all relocations are
	# resolved, and returns the raw string version
	def encode_string(*a)
		encode(*a)
		raise ["Unresolved relocations:", @encoded.reloc.map { |o, r| "#{r.target} " + (Backtrace.backtrace_str(r.backtrace) if r.backtrace).to_s }].join("\n") if not @encoded.reloc.empty?
		@encoded.data
	end

	# saves the result of +encode_string+ in the specified file
	# fails if the file already exists
	def encode_file(path, *a)
		raise Errno::EEXIST, path if File.exist? path	# race, but cannot use O_EXCL, as O_BINARY is not defined in ruby
		encode_string(*a)
		File.open(path, 'wb') { |fd| fd.write(@encoded.data) }
	end

	# converts a constant name to its numeric value using the hash
	# {1 => 'toto', 2 => 'tata'}: 'toto' => 1, 42 => 42, 'tutu' => raise
	def int_from_hash(val, hash)
		val.kind_of?(Integer) ? val : hash.index(val) or raise "unknown constant #{val.inspect}"
	end

	# converts an array of flag constants to its numeric value using the hash
	# {1 => 'toto', 2 => 'tata'}: ['toto', 'tata'] => 3, 'toto' => 2, 42 => 42
	def bits_from_hash(val, hash)
		val.kind_of?(Array) ? val.inject(0) { |val, bitname| val | int_from_hash(bitname, hash) } : int_from_hash(val, hash)
	end

	# converts a numeric value to the corresponding constant name using the hash
	# {1 => 'toto', 2 => 'tata'}: 1 => 'toto', 42 => 42, 'tata' => 'tata', 'tutu' => raise
	def int_to_hash(val, hash)
		val.kind_of?(Integer) ? hash.fetch(val, val) : (hash.index(val) ? val : raise("unknown constant #{val.inspect}"))
	end

	# converts a numeric value to the corresponding array of constant flag names using the hash
	# {1 => 'toto', 2 => 'tata'}: 5 => ['toto', 4]
	def bits_to_hash(val, hash)
		(val.kind_of?(Integer) ? (hash.find_all { |k, v| val & k == k and val &= ~k }.map { |k, v| v } << val) : val.kind_of?(Array) ? val.map { |e| int_to_hash(e, hash) } : [int_to_hash(val, hash)]) - [0]
	end
end
end
