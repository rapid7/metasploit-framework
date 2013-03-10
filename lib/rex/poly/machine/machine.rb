
module Rex

	module Poly

		#
		# A machine capable of creating a small blob of code in a metamorphic kind of way.
		# Note: this is designed to perform an exhaustive search for a solution and can be
		# slow. If you need a speedier option, the origional Rex::Polly::Block stuff is a
		# better choice.
		#
		class Machine

			QWORD = 8
			DWORD = 4
			WORD  = 2
			BYTE  = 1

			#
			# A Permutation!
			#
			class Permutation

				attr_accessor :active, :offset

				attr_reader :name, :primitive, :length, :args

				#
				# Create a new permutation object.
				#
				def initialize( name, primitive, machine, source, args=nil )
					@name      = name
					@primitive = primitive
					@machine   = machine
					@source    = source
					@args      = args
					@active    = false
					@valid     = true
					@length    = 0
					@offset    = 0
					@children  = ::Array.new
				end

				#
				# Add in a child permutation to this one. Used to build the permutation tree.
				#
				def add_child( child )
					@children << child
				end

				#
				# Does this permutation have children?
				#
				def has_children?
					not @children.empty?
				end

				#
				# Remove any existing children. Called by the machines generate function
				# to build a fresh tree in case generate was previously called.
				#
				def remove_children
					@children.clear
				end

				#
				# Actully render this permutation into a raw buffer.
				#
				def render
					raw   = ''
					# Zero the length as we will be rendering the raw buffer and the length may change.
					@length = 0
					# If this permutation source is a Primitive/Procedure we can call it, otherwise we have a string
					if( @source.kind_of?( Primitive ) or @source.kind_of?( ::Proc ) )
						if( @source.kind_of?( Primitive ) )
							raw = @source.call( @name, @machine, *@args )
						elsif( @source.kind_of?( ::Proc ) )
							raw = @source.call
						end
						# If the primitive/procedure returned an array, it is an array of assembly strings which we can assemble.
						if( raw.kind_of?( ::Array ) )
							lines = raw
							raw   = ''
							# itterate over each line of assembly
							lines.each do | asm |
								# parse the asm and substitute in any offset values specified...
								offsets = asm.scan( /:([\S]+)_offset/ )
								offsets.each do | name, |
									asm = asm.gsub( ":#{name}_offset", @machine.block_offset( name ).to_s )
								end
								# and substitute in and register values for any variables specified...
								regs = asm.scan( /:([\S]+)_reg([\d]+)/ )
								regs.each do | name, size |
									asm = asm.gsub( ":#{name}_reg#{size}", @machine.variable_value( name, size.to_i ) )
								end
								# assemble it into a raw blob
								blob = @machine.assemble( asm )
								#if( not @machine.is_valid?( blob ) )
								#	p "#{name}(#{primitive}):#{asm} is invalid"
								#end
								raw << blob
							end
						end
					else
						# the source must just be a static string
						raw = @source
					end
					# Update the length to reflect the new raw buffer
					@length = raw.to_s.length
					# As the temp variable is only assigned for the duration of a single permutation we
					# can now release it if it was used in this permutation.
					@machine.release_temp_variable
					return raw.to_s
				end

				#
				# Test if this permutation raw buffer is valid in this machine (e.g. against the badchar list).
				#
				def is_valid?
					result = false
					if( @valid )
						begin
							result = @machine.is_valid?( self.render )
						rescue UnallowedPermutation
							# This permutation is unallowed and can never be rendered so just mark it as
							# not valid to skip it during future attempts.
							@valid = false
						rescue UndefinedPermutation
							# allow an undefined permutation to fail validation but keep it marked
							# as valid as it may be defined and passed validation later.
						ensure
							# Should a temporary variable have been assigned we can release it here.
							@machine.release_temp_variable
						end
					end
					return result
				end

				#
				# Try to find a solution within the solution space by performing a depth first search
				# into the permutation tree and backtracking when needed.
				#
				def solve
					# Check to see if this permutation can make part of a valid solution
					if( self.is_valid? )
						# record this permutation as part of the final solution (the current machines register state is also saved here)
						@machine.solution_push( self )
						# If we have no children we are at the end of the tree and have a potential full solution.
						if( not self.has_children? )
							# We have a solution but doing a final pass to update offsets may introduce bad chars
							# so we test for this and keep searching if this isnt a real solution after all.
							if( not @machine.solution_is_valid? )
								# remove this permutation and keep searching
								@machine.solution_pop
								return false
							end
							# Return true to unwind the recursive call as we have got a final solution.
							return true
						end
						# Itterate over the children of this permutation (the perutations of the proceeding block).
						@children.each do | child |
							# Traverse into this child to keep trying to generate a solution...
							if( child.solve )
								# Keep returning true to unwind as we are done.
								return true
							end
						end
						# If we get here this permutation, origionally thought to be good for a solution, is not after all,
						# so remove it from the machines final solution, restoring the register state aswell.
						@machine.solution_pop
					end
					# No children can be made form part of the solution, return failure for this path in the tree.
					return false
				end

			end

			#
			# A symbolic permutation to mark locations like the begining and end of a group of blocks.
			# Used to calculate usefull offsets.
			#
			class SymbolicPermutation < Permutation
				def initialize( name, machine, initial_offset=0 )
					super( name, '', machine, '' )
					# fudge the initial symbolic offset with a default (it gets patched correctly later),
					# helps with the end symbolic block to not be 0 (as its a forward reference it really
					# slows things down if we leave it 0)
					@offset = initial_offset
					# A symbolic block is allways active!
					@active = true
				end

				#
				# We block all attempts to set the active state of this permutation so as
				# it is always true. This lets us always address the offset.
				#
				def active=( value )
				end
			end

			#
			# A primitive is a machine defined permutation which accepts some arguments when it is called.
			#
			class Primitive

				#
				# Initialize this primitive with its target source procedure and the machine it belongs to.
				#
				def initialize( source )
					@source = source
				end

				#
				# Call the primitives source procedure, passing in the arguments.
				#
				def call( name, machine, *args )
					return @source.call( name, machine, *args )
				end

			end

			#
			#
			#
			class Block

				#attr_accessor :next, :previous
				attr_reader :name

				def initialize( name )
					@name         = name
					@next         = nil
					@previous     = nil
					@permutations = ::Array.new
				end

				def shuffle
					@permutations = @permutations.shuffle
				end

				def solve
					@permutations.first.solve
				end

				def << ( permutation )
					@permutations << permutation
				end

				def each
					@permutations.each do | permutation |
						yield permutation
					end
				end

			end

			#
			# A class to hold a solution for a Rex::Poly::Machine problem.
			#
			class Solution

				attr_reader :offset

				def initialize
					@permutations = ::Array.new
					@reg_state    = ::Array.new
					@offset       = 0
				end

				#
				# Reset this solution to an empty state.
				#
				def reset
					@offset = 0
					@permutations.each do | permutation |
						permutation.active = false
						permutation.offset = 0
					end
					@permutations.clear
					@reg_state.clear
				end

				#
				# Push a new permutation onto this solutions permutations list and save the associated register/variables state
				#
				def push( permutation, reg_available, reg_consumed, variables )
					permutation.active = true
					permutation.offset = @offset
					@offset += permutation.length
					@permutations.push( permutation )
					@reg_state.push( [ [].concat(reg_available), [].concat(reg_consumed), {}.merge(variables) ] )
				end

				#
				# Pop off the last permutaion and register/variables state from this solution.
				#
				def pop
					reg_available, reg_consumed, variables = @reg_state.pop
					permutation = @permutations.pop
					permutation.active = false
					permutation.offset = 0
					@offset -= permutation.length
					return permutation, reg_available, reg_consumed, variables
				end

				#
				# Render the final buffer.
				#
				def buffer
					previous_offset = nil
					count           = 0
					# perform an N-pass fixup for offsets...
					while( true ) do
						# If we cant get the offsets fixed within a fixed ammount of tries we return
						# nil to indicate failure and keep searching for a solution that will work.
						if( count > 64 )
							return nil
						end
						# Reset the solution offset so as to update it for this pass
						@offset = 0
						# perform a single pass to ensure we are using the correct offset values
						@permutations.each do | permutation |
							permutation.offset = @offset
							# Note: calling render() can throw both UndefinedPermutation and UnallowedPermutation exceptions,
							# however as we assume we only ever return the buffer once a final solution has been generated
							# we should never have either of those exceptions thrown.
							permutation.render
							@offset += permutation.length
						end
						# If we have generated two consecutive passes which are the same length we can stop fixing up the offsets.
						if( not previous_offset.nil? and @offset == previous_offset )
							break
						end
						count +=1
						previous_offset = @offset
					end
					# now a final pass to render the solution into the raw buffer
					raw = ''
					@permutations.each do | permutation |
						#$stderr.puts "#{permutation.name} - #{ "0x%08X (%d)" % [ permutation.offset, permutation.length] } "
						raw << permutation.render
					end
					return raw
				end

			end

			#
			# Create a new machine instance.
			#
			def initialize( badchars, cpu )
				@badchars      = badchars
				@cpu           = cpu

				@reg_available = ::Array.new
				@reg_consumed  = ::Array.new
				@variables     = ::Hash.new
				@blocks        = ::Hash.new
				@primitives    = ::Hash.new
				@solution      = Solution.new

				_create_primitives

				@blocks['begin'] = Block.new( 'begin' )
				@blocks['begin'] << SymbolicPermutation.new( 'begin', self )

				_create_variable( 'temp' )
			end

			#
			# Overloaded by a subclass to return the maximum native general register size supported.
			#
			def native_size
				nil
			end

			#
			# Use METASM to assemble a line of asm using this machines current cpu.
			#
			def assemble( asm )
				return Metasm::Shellcode.assemble( @cpu, asm ).encode_string
			end

			#
			# Check if a data blob is valid against the badchar list (or perform any other validation here)
			#
			def is_valid?( data )
				if( data.nil? )
					return false
				end
				return Rex::Text.badchar_index( data, @badchars ).nil?
			end

			#
			# Generate a 64 bit number whoes bytes are valid in this machine.
			#
			def make_safe_qword( number=nil )
				return _make_safe_number( QWORD, number ) & 0xFFFFFFFFFFFFFFFF
			end

			#
			# Generate a 32 bit number whoes bytes are valid in this machine.
			#
			def make_safe_dword( number=nil )
				return _make_safe_number( DWORD, number ) & 0xFFFFFFFF
			end

			#
			# Generate a 16 bit number whoes bytes are valid in this machine.
			#
			def make_safe_word( number=nil )
				return _make_safe_number( WORD, number ) & 0xFFFF
			end

			#
			# Generate a 8 bit number whoes bytes are valid in this machine.
			#
			def make_safe_byte( number=nil )
				return _make_safe_number( BYTE, number ) & 0xFF
			end

			#
			# Create a variable by name which will be assigned a register during generation. We can
			# optionally assign a static register value to a variable if needed.
			#
			def create_variable( name, reg=nil )
				# Sanity check we aren't trying to create one of the reserved variables.
				if( name == 'temp' )
					raise RuntimeError, "Unable to create variable, '#{name}' is a reserved variable name."
				end
				return _create_variable( name, reg )
			end

			#
			# If the temp variable was assigned we release it.
			#
			def release_temp_variable
				if( @variables['temp'] )
					regnum = @variables['temp']
					# Sanity check the temp variable was actually assigned (it may not have been if the last permutation didnot use it)
					if( regnum )
						# place the assigned register back in the available list for consumption later.
						@reg_available.push( @reg_consumed.delete( regnum ) )
						# unasign the temp vars register
						@variables['temp'] = nil
						return true
					end
				end
				return false
			end

			#
			# Resolve a variable name into its currently assigned register value.
			#
			def variable_value( name, size=nil )
				# Sanity check we this variable has been created
				if( not @variables.has_key?( name ) )
					raise RuntimeError, "Unknown register '#{name}'."
				end
				# Pull out its current register value if it has been assigned one
				regnum = @variables[ name ]
				if( not regnum )
					regnum = @reg_available.pop
					if( not regnum )
						raise RuntimeError, "Unable to assign variable '#{name}' a register value, none available."
					end
					# and add it to the consumed list so we can track it later
					@reg_consumed << regnum
					# and now assign the variable the register
					@variables[ name ] = regnum
				end
				# resolve the register number int a string representation (e.g. 0 in x86 is EAX if size is 32)
				return _register_value( regnum, size )
			end

			#
			# Check this solution is still currently valid (as offsets change it may not be).
			#
			def solution_is_valid?
				return self.is_valid?( @solution.buffer )
			end

			#
			# As the solution advances we save state for each permutation step in the solution. This lets
			# use rewind at a later stage if the solving algorithm wishes to perform some backtracking.
			#
			def solution_push( permutation )
				@solution.push( permutation, @reg_available, @reg_consumed, @variables  )
			end

			#
			# Backtrack one step in the solution and restore the register/variable state.
			#
			def solution_pop
				permutation, @reg_available, @reg_consumed, @variables = @solution.pop

				@reg_available.push( @reg_available.shift )
			end

			#
			# Create a block by name and add in its list of permutations.
			#
			# XXX: this doesnt support the fuzzy order of block dependencies ala the origional rex::poly
			def create_block( name, *permutation_sources )
				# Sanity check we aren't trying to create one of the reserved symbolic blocks.
				if( name == 'begin' or name == 'end' )
					raise RuntimeError, "Unable to add block, '#{name}' is a reserved block name."
				end
				# If this is the first time this block is being created, create the block object to hold the permutation list
				if( not @blocks[name] )
					@blocks[name] = Block.new( name )
				end
				# Now create a new permutation object for every one supplied.
				permutation_sources.each do | source |
					@blocks[name] << Permutation.new( name, '', self, source )
				end
				return name
			end

			#
			# Create a block which is based on a primitive defined by this machine.
			#
			def create_block_primitive( block_name, primitive_name, *args )
				# Santiy check this primitive is actually available and is not an internal primitive (begins with an _).
				if( not @primitives[primitive_name] or primitive_name[0] == "_" )
					raise RuntimeError, "Unable to add block, Primitive '#{primitive_name}' is not available."
				end
				# Sanity check we aren't trying to create one of the reserved symbolic blocks.
				if( block_name == 'begin' or block_name == 'end' )
					raise RuntimeError, "Unable to add block, '#{block_name}' is a reserved block name."
				end
				return _create_block_primitive( block_name, primitive_name, *args )
			end

			#
			# Get the offset for a blocks active permutation. This is easy for backward references as
			# they will already have been rendered and their sizes known. For forward references we
			# can't know in advance but the correct value can be known later once the final solution is
			# available and a final pass to generate the raw buffer is made.
			#
			def block_offset( name )
				if( name == 'end' )
					return @solution.offset
				elsif( @blocks[name] )
					@blocks[name].each do | permutation |
						if( permutation.active )
							return permutation.offset
						end
					end
				end
				# If we are forward referencing a block it will be at least the current solutions offset +1
				return @solution.offset + 1
			end

			#
			# Does a given block exist?
			#
			def block_exist?( name )
				return @blocks.include?( name )
			end

			#
			# Does a given block exist?
			#
			def variable_exist?( name )
				return @variables.include?( name )
			end

			# XXX: ambiguity between variable names and block name may introduce confusion!!! make them be unique.

			#
			# Resolve a given value into either a number literal, a block offset or
			# a variables assigned register.
			#
			def resolve_value( value, size=nil )
				if( block_exist?( value ) )
					return block_offset( value )
				elsif( variable_exist?( value ) )
					return variable_value( value, size )
				end
				return value.to_i
			end

			#
			# Get the block previous to the target block.
			#
			def block_previous( target_block )
				previous_block = nil
				@blocks.each_key do | current_block |
					if( current_block == target_block )
						return previous_block
					end
					previous_block = current_block
				end
				return nil
			end

			#
			# Get the block next to the target block.
			#
			def block_next( target_block )
				@blocks.each_key do | current_block |
					if( block_previous( current_block ) == target_block )
						return current_block
					end
				end
				return nil
			end

			#
			# Try to generate a solution.
			#
			def generate

				if( @blocks.has_key?( 'end' ) )
					@blocks.delete( 'end' )
				end

				@blocks['end'] = Block.new( 'end' )
				@blocks['end'] << SymbolicPermutation.new( 'end', self, 1 )

				# Mix up the permutation orders for each block and create the tree structure.
				previous = ::Array.new
				@blocks.each_value do | block |
					# Shuffle the order of the blocks permutations.
					block.shuffle
					# create the tree by adding the current blocks permutations as children of the previous block.
					current = ::Array.new
					block.each do | permutation |
						permutation.remove_children
						previous.each do | prev |
							prev.add_child( permutation )
						end
						current << permutation
					end
					previous = current
				end

				# Shuffle the order of the available registers
				@reg_available = @reg_available.shuffle

				# We must try every permutation of the register orders, so if we fail to
				# generate a solution we rotate the available registers to try again with
				# a different order. This ensures we perform and exhaustive search.
				0.upto( @reg_available.length - 1 ) do

					@solution.reset

					# Start from the root node in the solution space and generate a
					# solution by traversing the solution space's tree structure.
					if( @blocks['begin'].solve )
						# Return the solutions buffer (perform a last pass to fixup all offsets)...
						return @solution.buffer
					end

					@reg_available.push( @reg_available.shift )
				end

				# :(
				nil
			end

			#
			# An UndefinedPermutation exception is raised when a permutation can't render yet
			# as the conditions required are not yet satisfied.
			#
			class UndefinedPermutation < RuntimeError
				def initialize( msg=nil )
					super
				end
			end

			#
			# An UnallowedPermutation exception is raised when a permutation can't ever render
			# as the conditions supplied are impossible to satisfy.
			#
			class UnallowedPermutation < RuntimeError
				def initialize( msg=nil )
					super
				end
			end

			#
			# An InvalidPermutation exception is raised when a permutation receives a invalid
			# argument and cannot continue to render. This is a fatal exception.
			#
			class InvalidPermutation < RuntimeError
				def initialize( msg=nil )
					super
				end
			end

			protected

			#
			# Overloaded by a subclass to resolve a register number into a suitable register
			# name for the target architecture. E.g on x64 the register number 0 with size 64
			# would resolve to RCX. Size is nil by default to indicate we want the default
			# machine size, e.g. 32bit DWORD on x86 or 64bit QWORD on x64.
			#
			def _register_value( regnum, size=nil )
				nil
			end

			#
			# Perform the actual variable creation.
			#
			def _create_variable( name, reg=nil )
				regnum = nil
				# Sanity check this variable has not already been created.
				if( @variables[name] )
					raise RuntimeError, "Variable '#{name}' is already created."
				end
				# If a fixed register is being assigned to this variable then resolve it
				if( reg )
					# Resolve the register name into a register number
					@reg_available.each do | num |
						if( _register_value( num ) == reg.downcase )
							regnum = num
							break
						end
					end
					# If an invalid register name was given or the chosen register is not available we must fail.
					if( not regnum )
						raise RuntimeError, "Register '#{reg}' is unknown or unavailable."
					end
					# Sanity check another variable isnt assigned this register
					if( @variables.has_value?( regnum ) )
						raise RuntimeError, "Register number '#{regnum}' is already consumed by variable '#{@variables[name]}'."
					end
					# Finally we consume the register chosen so we dont select it again later.
					@reg_consumed << @reg_available.delete( regnum )
				end
				# Create the variable and assign it a register number (or nil if not yet assigned)
				@variables[name] = regnum
				return name
			end

			#
			# Create a block which is based on a primitive defined by this machine.
			#
			def _create_block_primitive( block_name, primitive_name, *args )
				# If this is the first time this block is being created, create the array to hold the permutation list
				if( not @blocks[block_name] )
					@blocks[block_name] = Block.new( block_name )
				end
				# Now create a new permutation object for every one supplied.
				@primitives[primitive_name].each do | source |
					@blocks[block_name] << Permutation.new( block_name, primitive_name, self, source, args )
				end
				return block_name
			end

			#
			# Overloaded by a subclass to create any primitives available in this machine.
			#
			def _create_primitives
				nil
			end

			#
			# Rex::Poly::Machine::Primitive
			#
			def _create_primitive( name, *permutations )
				# If this is the first time this primitive is being created, create the array to hold the permutation list
				if( not @primitives[name] )
					@primitives[name] = ::Array.new
				end
				# Add in the permutation object (Rex::Poly::Machine::Primitive) for every one supplied.
				permutations.each do | permutation |
					@primitives[name] << Primitive.new( permutation )
				end
			end

			#
			# Helper function to generate a number whoes byte representation is valid in this
			# machine (does not contain any badchars for example). Optionally we can supply a
			# number and the resulting addition/subtraction of this number against the newly
			# generated value is also tested for validity. This helps in the assembly primitives
			# which can use these values.
			#
			def _make_safe_number( bytes, number=nil )
				format = ''
				if( bytes == BYTE )
					format = 'C'
				elsif( bytes == WORD )
					format = 'v'
				elsif( bytes == DWORD )
					format = 'V'
				elsif( bytes == QWORD )
					format = 'Q'
				else
					raise RuntimeError, "Invalid size '#{bytes}' used in _make_safe_number."
				end

				goodchars = (0..255).to_a

				@badchars.unpack( 'C*' ).each do | b |
					goodchars.delete( b.chr )
				end

				while( true ) do
					value = 0

					0.upto( bytes-1 ) do | i |
						value |= ( (goodchars[ rand(goodchars.length) ] << i*8) & (0xFF << i*8) )
					end

					if( not is_valid?( [ value ].pack(format) ) or not is_valid?( [ ~value ].pack(format) ) )
						redo
					end

					if( not number.nil? )
						if(	not is_valid?( [ value + number ].pack(format) ) or not is_valid?( [ value - number ].pack(format) ) )
							redo
						end
					end

					break
				end

				return value
			end

		end

	end

end
