#!/usr/bin/ruby

# Rex::Struct2
module Rex
module Struct2

require 'Rex/Struct2/SStruct'

class CStruct_Values

	def initialize(obj)
		@obj = obj
	end

	def [](*args)
		o = @obj[*args]
		return if !o
		return o.value
	end

	def []=(*args)
		o = @obj[*args[0 .. -2]]
		return if !o
		o.value = args[-1]
	end

	# this one is for HD, the whiniest girl around...
	# allow for like v.field = whatever
	def method_missing(sym, *args)
		if sym.to_s[-1] == "="[0]
			return self[sym.to_s[0 .. -2]] = args[0]
		else
			return self[sym.to_s]
		end
	end
end

class CStruct < SStruct

	require 'Rex/Struct2/Element'
	require 'Rex/Struct2/Generic'
	require 'Rex/Struct2/SString'
	require 'Rex/Struct2/CStructTemplate'
	require 'Rex/Struct2/Restraint'

	include Rex::Struct2::Element

	attr_reader  :v

	@@dt_table = {
	  'uint8'     => [ proc { |*a| Rex::Struct2::Generic.new(*a) }, 'C' ],
	  'uint16v'   => [ proc { |*a| Rex::Struct2::Generic.new(*a) }, 'v' ],
	  'uint32v'   => [ proc { |*a| Rex::Struct2::Generic.new(*a) }, 'V' ],
	  'uint16n'   => [ proc { |*a| Rex::Struct2::Generic.new(*a) }, 'n' ],
	  'uint32n'   => [ proc { |*a| Rex::Struct2::Generic.new(*a) }, 'N' ],
	  'string'    => [ proc { |*a| Rex::Struct2::SString.new(*a) } ],
	  'sstruct'   => [ proc { |*a| Rex::Struct2::SStruct.new(*a) } ],
	  'object'    => [ proc { |o| o } ], # no class, treat as object...
	  'struct'    => [ proc { |o| o } ], # no class, treat as object...
	  'cstruct'   => [ proc { |o| o } ], # no class, treat as object...
	  'template'  => [ proc { |o| o.make_struct } ],
	}

	def initialize(*dts)
		super()
		@name_table = [ ]
		@v = Rex::Struct2::CStruct_Values.new(self)

		return self.add_from_dt(*dts)
	end

	def add_from_dt(*dts)
		dts.each { | dt |
			return if !dt.kind_of?(Array) || dt.length < 2

			type = dt[0]
			name = dt[1]

			entry = @@dt_table[type]

			return if !entry

			factory = entry[0]

			obj = factory.call(*(entry[1 .. -1] + dt[2 .. -1]))

			self.add_object(name, obj)
		}

		return dts.length
	end

	def add_object(*objs)
		while objs.length >= 2
			@name_table << objs.shift
			self        << objs.shift
		end
	end
	# apply_restraint( name, restraint, name2, restraint2 ... )
	def apply_restraint(*ress)
		while ress.length >= 2
			name = ress.shift
			res  = ress.shift
			self[name].restraint = res
		end
		return self
	end

	# create_restraints( [ name, stuff_to_restraint_constructor ] ... )
	def create_restraints(*ress)
		ress.each { |r|
			# make a copy before we modify...
			r = r.dup
			# resolve names into objects
			r[1] = self[r[1]] if r[1]
			r[2] = self[r[2]] if r[2]

			# build and apply the restraint
			self.apply_restraint(r[0], Rex::Struct2::Restraint.new(*r[1 .. -1]))
		}

		return self
	end

	# ya ya, I know, these are weird.  I'm not sure why I even bothered
	# to inherit from array...
	def [](index, *other)
		if index.kind_of?(String)
			i = @name_table.index(index)
			return if !i
			return super(i)
		else
			return super(index, *other)
		end
	end

	def []=(index, *other)
		if index.kind_of?(String)
			i = @name_table.index(index)
			return if !i
			return super(i, *other)
		else
			return super(index, *other)
		end
	end
end

# end Rex::Struct2
end
end
