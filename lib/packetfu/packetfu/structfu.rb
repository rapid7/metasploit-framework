# -*- coding: binary -*-
# StructFu, a nifty way to leverage Ruby's built in Struct class
# to create meaningful binary data. 

module StructFu
	
	# Normally, self.size and self.length will refer to the Struct
	# size as an array. It's a hassle to redefine, so this introduces some
	# shorthand to get at the size of the resultant string.
	def sz
		self.to_s.size
	end

	alias len sz

	# Typecast is used mostly by packet header classes, such as IPHeader,
	# TCPHeader, and the like. It takes an argument, and casts it to the
	# expected type for that element. 
	def typecast(i)
		c = caller[0].match(/.*`([^']+)='/)[1]
		self[c.intern].read i
	end

	# Used like typecast(), but specifically for casting Strings to StructFu::Strings.
	def body=(i)
		if i.kind_of? ::String
			typecast(i)
		elsif i.kind_of? StructFu
			self[:body] = i
		elsif i.nil?
			self[:body] = StructFu::String.new.read("")
		else
			raise ArgumentError, "Can't cram a #{i.class} into a StructFu :body"
		end
	end

	# Handle deep copies correctly. Marshal in 1.9, re-read myself on 1.8
	def clone
		begin
			Marshal.load(Marshal.dump(self))
		rescue
			self.class.new.read(self.to_s)
		end
	end

	# Ints all have a value, an endianness, and a default value.
	# Note that the signedness of Int values are implicit as
	# far as the subclasses are concerned; to_i and to_f will 
	# return Integer/Float versions of the input value, instead
	# of attempting to unpack the pack value. (This can be a useful
	# hint to other functions).
	#
	# ==== Header Definition
	#
	#   Fixnum  :value
	#   Symbol  :endian
	#   Fixnum  :width
	#   Fixnum  :default
	class Int < Struct.new(:value, :endian, :width, :default)
		alias :v= :value=
		alias :v :value
		alias :e= :endian=
		alias :e :endian
		alias :w= :width=
		alias :w :width
		alias :d= :default=
		alias :d :default

		# This is a parent class definition and should not be used directly.
		def to_s
			raise StandardError, "StructFu::Int#to_s accessed, must be redefined."
		end

		# Returns the Int as an Integer.
		def to_i
			(self.v || self.d).to_i
		end

		# Returns the Int as a Float.
		def to_f
			(self.v || self.d).to_f
		end
		
		def initialize(value=nil, endian=nil, width=nil, default=nil)
			super(value,endian,width,default=0)
		end

		# Reads either an Integer or a packed string, and populates the value accordingly.
		def read(i)
			self.v = i.kind_of?(Integer) ? i.to_i : i.to_s.unpack(@packstr).first
			self
		end

	end

	# Int8 is a one byte value.
	class Int8 < Int

		def initialize(v=nil)
			super(v,nil,w=1)
			@packstr = "C"
		end

		# Returns a one byte value as a packed string.
		def to_s
		 [(self.v || self.d)].pack("C")
		end

	end

	# Int16 is a two byte value.
	class Int16 < Int
		def initialize(v=nil, e=:big)
			super(v,e,w=2)
			@packstr = (self.e == :big) ? "n" : "v"
		end

		# Returns a two byte value as a packed string.
		def to_s
			@packstr = (self.e == :big) ? "n" : "v"
			[(self.v || self.d)].pack(@packstr)
	 	end

	end
  
	# Int16be is a two byte value in big-endian format. The endianness cannot be altered.
	class Int16be < Int16
		undef :endian=
	end

	# Int16le is a two byte value in little-endian format. The endianness cannot be altered.
	class Int16le < Int16
		undef :endian=
		def initialize(v=nil, e=:little)
			super(v,e)
			@packstr = (self.e == :big) ? "n" : "v"
		end
	end

	# Int32 is a four byte value.
	class Int32 < Int
		def initialize(v=nil, e=:big)
			super(v,e,w=4)
			@packstr = (self.e == :big) ? "N" : "V"
		end

		# Returns a four byte value as a packed string.
		def to_s
			@packstr = (self.e == :big) ? "N" : "V"
			[(self.v || self.d)].pack(@packstr)
	 	end

	end

	# Int32be is a four byte value in big-endian format. The endianness cannot be altered.
	class Int32be < Int32
		undef :endian=
	end

	# Int32le is a four byte value in little-endian format. The endianness cannot be altered.
	class Int32le < Int32
		undef :endian=
		def initialize(v=nil, e=:little)
			super(v,e)
		end
	end

	# Strings are just like regular strings, except it comes with a read() function
	# so that it behaves like other StructFu elements.
	class String < ::String
		def read(str)
			str = str.to_s
			self.replace str
			self
		end
	end

	# Provides a primitive for creating strings, preceeded by
	# an Int type of length. By default, a string of length zero with
	# a one-byte length is presumed.  
	#
	# Note that IntStrings aren't used for much, but it seemed like a good idea at the time.
	class IntString < Struct.new(:int, :string, :mode)

		def initialize(string='',int=Int8,mode=nil)
			if int < Int
				super(int.new,string,mode)
				calc
			else
				raise "IntStrings need a StructFu::Int for a length."
			end
		end

		# Calculates the size of a string, and sets it as the value.
		def calc
			int.v = string.to_s.size
			self.to_s
		end

		# Returns the object as a string, depending on the mode set upon object creation.
		def to_s
			if mode == :parse
				"#{int}" + [string].pack("a#{len}")
			elsif mode == :fix
				self.int.v = string.size
				"#{int}#{string}"
			else
				"#{int}#{string}"
			end
		end

		# By redefining #string=, we can ensure the correct value
		# is calculated upon assignment. If you'd prefer to have
		# an incorrect value, use the syntax, obj[:string]="value"
		# instead. Note, by using the alternate form, you must
		# #calc before you can trust the int's value. Think of the = 
		# assignment as "set to equal," while the []= assignment
		# as "boxing in" the value. Maybe.
		def string=(s)
			self[:string] = s
			calc
		end

		# Shorthand for querying a length. Note that the usual "length"
		# and "size" refer to the number of elements of this struct.
		def len
			self[:int].value
		end

		# Override the size, if you must.
		def len=(i)
			self[:int].value=i
		end

		# Read takes a string, assumes an int width as previously
		# defined upon initialization, but makes no guarantees
		# the int value isn't lying. You're on your own to test
		# for that (or use parse() with a :mode set).
		def read(s)
			unless s[0,int.width].size == int.width
				raise StandardError, "String is too short for type #{int.class}"
			else
				int.read(s[0,int.width])
				self[:string] = s[int.width,s.size]
			end
			self.to_s
		end

		# parse() is like read(), except that it interprets the string, either
		# based on the declared length, or the actual length. Which strategy
		# is used is dependant on which :mode is set (with self.mode).
		#
		# :parse : Read the length, and then read in that many bytes of the string. 
		# The string may be truncated or padded out with nulls, as dictated by the value.
		#
		# :fix   : Skip the length, read the rest of the string, then set the length 
		# to what it ought to be.
		#
		# else   : If neither of these modes are set, just perfom a normal read().
		# This is the default.
		def parse(s)
			unless s[0,int.width].size == int.width
				raise StandardError, "String is too short for type #{int.class}"
			else
				case mode 
				when :parse
					int.read(s[0,int.width])
					self[:string] = s[int.width,int.value]
					if string.size < int.value
						self[:string] += ("\x00" * (int.value - self[:string].size))
					end
				when :fix
					self.string = s[int.width,s.size]
				else
					return read(s)
				end
			end
			self.to_s
		end

	end

end

class Struct

	# Monkeypatch for Struct to include some string safety -- anything that uses
	# Struct is going to presume binary strings anyway.
	def force_binary(str)
		PacketFu.force_binary(str)
	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
