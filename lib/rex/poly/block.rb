module Rex
module Poly

###
#
# This class encapsulates a LogicalBlock permutation.  Block permutations can
# take the form of a static string or a procedure.  This makes it possible to
# have simple blocks and more complicated ones that take into account other
# variables, such as dynamic registers.  The to_s method will return the
# string version of the permutation, regardless of whether or not the
# underlying permutation is a string or a procedure.
#
###
class Permutation

	#
	# Initializes the permutation and its associated block.
	#
	def initialize(perm, block)
		@perm  = perm
		@block = block
	end

	#
	# Returns the length of the string returned by to_s.
	#
	def length
		to_s.length
	end

	#
	# Returns the string representation of the permutation.  If the underlying
	# permutation is a procedure, the procedure is called.  Otherwise, the
	# string representation of the permutation is returned.
	#
	def to_s
		if (@perm.kind_of?(Proc))
			@perm.call(@block).to_s
		else
			@perm.to_s
		end
	end

end

###
#
# This class represents a logical block which is defined as a concise portion
# of code that may have one or more functionally equivalent implementations.
# A logical block should serve a very specific purpose, and any permutations
# beyond the first should result in exactly the same functionality without any
# adverse side effects to other blocks.  
#
# Like blocks of code, LogicalBlock's can depend on one another in terms of
# ordering and precedence.  By marking blocks as dependent on another, a
# hierarchy begins to form.  This is a block dependency graph.
#
# To add permutations to a LogicalBlock, they can either be passed in as a
# list of arguments to the constructor following the blocks name or can be
# added on the fly by calling the add_perm method.  To get a random
# permutation, the rand_perm method can be called.
#
# To mark one block as depending on another, the depends_on method can be
# called with zero or more LogicalBlock instances as parameters.
#
###
class LogicalBlock

	#
	# Initializes the logical block's name along with zero or more specific
	# blocks.
	#
	def initialize(name, *perms)
		@name  = name

		reset

		add_perm(*perms)
	end

	#
	# Resets the block back to its starting point.
	#
	def reset
		@perms    = []
		@depends  = []
		@clobbers = []
		@offset   = nil
		@state    = nil
	end

	#
	# Adds zero or more specific permutations that may be represented either as
	# strings or as Proc's to be called at evaluation time.
	#
	def add_perm(*perms)
		@perms.concat(perms)
	end

	#
	# Returns a random permutation that is encapsulated in a Permutation class
	# instance.
	#
	def rand_perm
		Permutation.new(@perms[rand(@perms.length)], self)
	end

	#
	# Sets the blocks that this block instance depends on.
	#
	def depends_on(*depends)
		@depends = depends.dup
	end

	#
	# Defines the list of zero or more LogicalRegister's that this block
	# clobbers.
	#
	def clobbers(*registers)
		@clobbers = registers
	end

	#
	# Enumerates each register instance that is clobbered by this block.
	#
	def each_clobbers(&block)
		@clobbers.each(&block)
	end

	#
	# Generates the polymorphic buffer that results from this block and any of
	# the blocks that it either directly or indirectly depends on.  A list of
	# register numbers to be saved can be passed in as an argument.
	#
	# This method is not thread safe.  To call this method on a single block
	# instance from within multiple threads, be sure to encapsulate the calls
	# inside a locked context.
	#
	def generate(save_registers = nil, state = nil)
		# Create a localized state instance if one was not supplied.
		state = Rex::Poly::State.new if (state == nil)

		# Reset the state in case it was passed in.
		state.reset

		# Consume any registers that should be saved.
		save_registers.each { |reg|
			state.consume_regnum(reg)
		} if (save_registers)

		# Build the linear list of blocks that will be processed.  This
		# list is built in a dynamic fashion based on block dependencies.
		# The list that is returned is an Array of which each element is a two
		# member array, the first element being the LogicalBlock instance that
		# the permutation came from and the second being an instance of the
		# Permutation class associated with the selected permutation.
		block_list = generate_block_list(state)

		# Transition into the second phase which enables offset_of and regnum_of
		# calls to return real values.
		state.first_phase = false

		# Now that every block has been assigned an offset, generate the
		# buffer block by block, assigning registers as necessary.
		block_list.each { |b| 

			# Generate the next permutation and append it to the buffer.
			begin
				state.buffer += b[1].to_s 
			# If an invalid register exception is raised, try to consume a random
			# register from the register's associated architecture register
			# number set.
			rescue InvalidRegisterError => e
				e.reg.regnum = state.consume_regnum_from_set(e.reg.class.regnum_set)
				retry
			end
	
			# Remove any of the registers that have been clobbered by this block
			# from the list of consumed register numbers so that they can be used
			# in the future.
			b[0].each_clobbers { |reg|
				begin
					state.defecate_regnum(reg.regnum)

					reg.regnum = nil
				rescue InvalidRegisterError
				end
			}
				
		}

		# Finally, return the buffer that has been created.
		state.buffer
	end

	#
	# Returns the offset of a block.  If the active state for this instance is
	# operating in the first phase, then zero is always returned.  Otherwise,
	# the correct offset for the supplied block is returned.
	#
	def offset_of(lblock)
		if (@state.first_phase) 
			0 
		else
			if (lblock.kind_of?(SymbolicBlock::End))
				@state.curr_offset
			else
				lblock.offset
			end
		end
	end

	#
	# Returns the register number associated with the supplied LogicalRegister
	# instance.  If the active state for this instance is operating in the
	# first phase, then zero is always returned.  Otherwise, the correct
	# register number is returned based on what is currently assigned to the
	# supplied LogicalRegister instance, if anything.
	#
	def regnum_of(reg)
		(@state.first_phase) ? 0 : reg.regnum
	end

	#
	# This attributes contains the currently assigned offset of the permutation
	# associated with this block into the polymorphic buffer that is being
	# generated.
	#
	attr_accessor :offset

protected

	#
	# Generates the linear of list of block permutation which is stored in the
	# supplied state instance.  This is done prior to assigning blocks offsets
	#
	def generate_block_list(state)

		# Generate dependencies first in a random order
		depend_idx = rand(@depends.length)

		@depends.length.times { |x|
		
			# Generate this block
			@depends[(depend_idx + x) % @depends.length].generate_block_list(state)
		}

		# Assign the instance local state for the duration of this generation
		@state = state

		# Select a random permutation
		perm = rand_perm

		# Set our block offset to the current state offset
		self.offset = state.curr_offset

		# Adjust the current offset based on the permutations length
		state.curr_offset += perm.length

		# Add it to the linear list of blocks
		state.block_list << [ self, perm ]
	end

end

###
#
# Symbolic blocks are used as special-case LogicalBlock's that have meaning
# a more general meaning.  For instance, SymbolicBlock::End can be used to
# symbolize the end of a polymorphic buffer.
#
###
module SymbolicBlock

	###
	#
	# The symbolic end of a polymorphic buffer.
	#
	###
	class End < LogicalBlock
		def initialize
			super('__SYMBLK_END__')
		end
	end
end

end
end
