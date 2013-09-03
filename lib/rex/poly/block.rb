# -*- coding: binary -*-
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

	attr_reader :perm

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
		@perms           = []
		@depends         = []
		@next_blocks     = []
		@clobbers        = []
		@offset          = nil
		@state           = nil
		@once            = false
		@references      = 0
		@used_references = 0
		@generated       = false
	end

	#
	# Returns the block's name.
	#
	def name
		@name
	end

	#
	# Flags whether or not the block should only be generated once.  This can
	# be used to mark a blog as being depended upon by multiple blocks, but
	# making it such that it is only generated once.
	#
	def once=(tf)
		@once = tf
	end

	#
	# Returns true if this block is a 'once' block.  That is, this block is
	# dependend upon by multiple blocks but should only be generated once.
	#
	def once
		@once
	end

	#
	# Increments the number of blocks that depend on this block.
	#
	# @see #deref
	def ref
		@references += 1
	end

	#
	# Increments the number of blocks that have completed their dependency
	# pass on this block.  This number should never become higher than the
	# `@references` attribute.
	#
	# @see #ref
	def deref
		@used_references += 1
	end

	#
	# Returns true if there is only one block reference remaining.
	#
	def last_reference?
		(@references - @used_references <= 0)
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
		perm = nil

		if (@state.badchars)
			perm = rand_perm_badchars
		else
			perm = Permutation.new(@perms[rand(@perms.length)], self)
		end

		if (perm.nil?)
			raise RuntimeError, "Failed to locate a valid permutation."
		end

		perm
	end

	#
	# Returns a random permutation that passes any necessary bad character
	# checks.
	#
	def rand_perm_badchars
		idx = rand(@perms.length)
		off = 0

		while (off < @perms.length)
			p = @perms[(idx + off) % @perms.length]

			if (p.kind_of?(Proc) or
			    @state.badchars.nil? or
			    Rex::Text.badchar_index(p, @state.badchars).nil?)
				return Permutation.new(p, self)
			end

			off += 1
		end
	end

	#
	# Sets the blocks that this block instance depends on.
	#
	def depends_on(*depends)
		@depends = depends.dup

		# Increment dependent references
		@depends.each { |b| b.ref }
	end

	#
	# Defines the next blocks, but not in a dependency fashion but rather in a
	# linking of separate block contexts.
	#
	def next_blocks(*blocks)
		@next_blocks = blocks.dup
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
	def generate(save_registers = nil, state = nil, badchars = nil)
		# Create a localized state instance if one was not supplied.
		state = Rex::Poly::State.new if (state == nil)
		buf   = nil
		cnt   = 0

		# This is a lame way of doing this.  We just try to generate at most 128
		# times until we don't have badchars.  The reason we have to do it this
		# way is because of the fact that badchars can be introduced through
		# block offsetting and register number selection which can't be readily
		# predicted or detected during the generation phase.  In the future we
		# can make this better, but for now this will have to do.
		begin
			buf = do_generate(save_registers, state, badchars)

			if (buf and
			    (badchars.nil? or Rex::Text.badchar_index(buf, badchars).nil?))
				break
			end
		end while ((cnt += 1) < 128)

		# If we passed 128 tries, then we can't succeed.
		buf = nil if (cnt >= 128)

		buf
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

	def size_of(lblock)
		@state.block_list.map { |b, p|
			if b == lblock
				return p.length
			end
		}
		0
	end

	#
	# This attributes contains the currently assigned offset of the permutation
	# associated with this block into the polymorphic buffer that is being
	# generated.
	#
	attr_accessor :offset

	#
	# Whether or not this block has currently been generated for a given
	# iteration.
	#
	attr_accessor :generated

protected

	#
	# Performs the actual polymorphic buffer generation.  Called from generate
	#
	def do_generate(save_registers, state, badchars)
		# Reset the state in case it was passed in.
		state.reset

		# Set the bad character list
		state.badchars = badchars if (badchars)

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
	# Generates the linear list of block permutations which is stored in the
	# supplied state instance.  This is done prior to assigning blocks offsets
	#
	def generate_block_list(state, level=0)
		if @depends.length > 1
			@depends.length.times {
				f = rand(@depends.length)
				@depends.push(@depends.delete_at(f))
			}
		end

		@depends.length.times { |cidx|

			pass = false

			while (not pass)

				if (@depends[cidx].generated)
					break

				# If this dependent block is a once block and the magic 8 ball turns
				# up zero, skip it and let a later block pick it up.  We only do this
				# if we are not the last block to have a dependency on this block.
				elsif ((@depends[cidx].once) and
			    	(rand(2).to_i == 0) and
			    	(@depends[cidx].last_reference? == false))
					break
				end

				# Generate this block
				@depends[cidx].generate_block_list(state, level+1)

				if level != 0
					return
				else
					@depends.length.times {
						f = rand(@depends.length)
						@depends.push(@depends.delete_at(f))
					}

					next
				end
			end

			next
		}

		self.deref

		# Assign the instance local state for the duration of this generation
		@state = state

		# Select a random permutation
		perm = rand_perm

		# Set our block offset to the current state offset
		self.offset = state.curr_offset

		# Flag ourselves as having been generated for this iteration.
		self.generated = true

		# Adjust the current offset based on the permutations length
		state.curr_offset += perm.length

		# Add it to the linear list of blocks
		state.block_list << [ self, perm ]

		# Generate all the blocks that follow this one.
		@next_blocks.each { |b|
			b.generate_block_list(state)
		}

		# Return the state's block list
		state.block_list
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
