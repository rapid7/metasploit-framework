
require 'rex/poly/machine'

module Rex

module Encoder

	class BloXor < Msf::Encoder

		def initialize( *args )
			super
			@machine    = nil
			@blocks_out = []
			@block_size = 0
		end

		#
		#
		#
		def decoder_stub( state )

			if( not state.decoder_stub )
				@blocks_out = []
				@block_size = 0

				# XXX: It would be ideal to use a random block size but unless we know the maximum size our final encoded
				# blob can be we should instead start with the smallest block size and go up to avoid generating
				# anything too big (if we knew the max size we could try something smaller if we generated a blob too big)
				#block_sizes = (1..state.buf.length).to_a.shuffle
				#block_sizes.each do | len |

				1.upto( state.buf.length ) do | len |

					# For now we ignore all odd sizes to help with performance (The rex poly machine
					# doesnt have many load/store primitives that can handle byte sizes efficiently)
					if( len % 2 != 0 )
						next
					end

					blocks, size = compute_encoded( state, len )
					if( blocks and size )

						# We sanity check that the newly generated block ammount and the block size
						# are not in the badchar list when converted into a hex form. Helps speed
						# things up a great deal when generating a decoder stub later as these
						# values may be used throughout.

						if( not number_is_valid?( state, blocks.length - 1 ) or not number_is_valid?( state, ~( blocks.length - 1 ) ) )
							next
						end

						if( not number_is_valid?( state, size ) or not number_is_valid?( state, ~size ) )
							next
						end

						@blocks_out = blocks
						@block_size = size

						break
					end
				end

				raise RuntimeError, "Unable to generate seed block." if( @blocks_out.empty? )

				state.decoder_stub = compute_decoder( state )
			end

			state.decoder_stub
		end

		#
		#
		#
		def encode_block( state, data )

			buffer = ''

			@blocks_out.each do | block |
				buffer << block.pack( 'C*' )
			end

			buffer
		end

		protected

		#
		# Is a number in its byte form valid against the badchars?
		#
		def number_is_valid?( state, number )
			size = 'C'
			if( number > 0xFFFF )
				size = 'V'
			elsif( number > 0xFF )
				size = 'v'
			end
			return Rex::Text.badchar_index( [ number ].pack( size ), state.badchars ).nil?
		end

		#
		# Calculate Shannon's entropy.
		#
		def entropy( data )
			entropy = 0.to_f
			(0..255).each do | byte |
				freq = data.to_s.count( byte.chr ).to_f / data.to_s.length
				if( freq > 0 )
					entropy -= freq * Math.log2( freq )
				end
			end
			return entropy / 8
		end

		#
		# Compute the encoded blocks (and associated seed)
		#
		def compute_encoded( state, len )

			blocks_in = ::Array.new

			input = '' << state.buf

			block_padding = ( input.length % len ) > 0 ? len - ( input.length % len ) : 0

			if( block_padding > 0 )
				0.upto( block_padding-1 ) do
					input << [ rand( 255 ) ].pack( 'C' )
				end
			end

			while( input.length > 0 )
				blocks_in << input[0..len-1].unpack( 'C*' )
				input = input[len..input.length]
			end

			seed = compute_seed( blocks_in, len, block_padding, state.badchars.unpack( 'C*' ) )

			if( not seed )
				return [ nil, nil ]
			end

			blocks_out = [ seed ]

			blocks_in.each do | block |
				blocks_out << compute_block( blocks_out.last, block )
			end

			return [ blocks_out, len ]
		end

		#
		# Generate the decoder stub which is functionally equivalent to the following:
		#
		#	source  = &end;
		#	dest    = source + BLOCK_SIZE;
		#	counter = BLOCK_COUNT * ( BLOCK_SIZE / chunk_size );
		#	do
		#	{
		#		encoded = *(CHUNK_SIZE *)dest;
		#		dest += chunk_size;
		#		decoded = *(CHUNK_SIZE *)source;
		#		*(CHUNK_SIZE *)source = decoded ^ encoded;
		#		source += chunk_size;
		#	} while( --counter );
		#
		#	end:
		#
		def compute_decoder( state )

			@machine.create_variable( 'source' )
			@machine.create_variable( 'dest' )
			@machine.create_variable( 'counter' )
			@machine.create_variable( 'encoded' )
			@machine.create_variable( 'decoded' )

			chunk_size = Rex::Poly::Machine::BYTE
			if( @machine.native_size() == Rex::Poly::Machine::QWORD )
				if( @block_size % Rex::Poly::Machine::QWORD == 0 )
					chunk_size = Rex::Poly::Machine::QWORD
				elsif( @block_size % Rex::Poly::Machine::DWORD == 0 )
					chunk_size = Rex::Poly::Machine::DWORD
				elsif( @block_size % Rex::Poly::Machine::WORD == 0 )
					chunk_size = Rex::Poly::Machine::WORD
				end
			elsif( @machine.native_size() == Rex::Poly::Machine::DWORD )
				if( @block_size % Rex::Poly::Machine::DWORD == 0 )
					chunk_size = Rex::Poly::Machine::DWORD
				elsif( @block_size % Rex::Poly::Machine::WORD == 0 )
					chunk_size = Rex::Poly::Machine::WORD
				end
			elsif( @machine.native_size() == Rex::Poly::Machine::WORD )
				if( @block_size % Rex::Poly::Machine::WORD == 0 )
					chunk_size = Rex::Poly::Machine::WORD
				end
			end

			# Block 1 - Set the source variable to the address of the start block
			@machine.create_block_primitive( 'block1', 'set', 'source', 'location' )

			# Block 2 - Set the source variable to the address of the 1st encoded block
			@machine.create_block_primitive( 'block2', 'add', 'source', 'end' )

			# Block 3 - Set the destingation variable to the value of the source variable
			@machine.create_block_primitive( 'block3', 'set', 'dest', 'source' )

			# Block 4 - Set the destingation variable to the address of the 2nd encoded block
			@machine.create_block_primitive( 'block4', 'add', 'dest', @block_size )

			# Block 5 - Sets the loop counter to the number of blocks to process
			@machine.create_block_primitive( 'block5', 'set', 'counter', ( ( @block_size / chunk_size ) * (@blocks_out.length - 1) ) )

			# Block 6 - Set the encoded variable to the byte pointed to by the dest variable
			@machine.create_block_primitive( 'block6', 'load', 'encoded', 'dest', chunk_size )

			# Block 7 - Increment the destination variable by one
			@machine.create_block_primitive( 'block7', 'add', 'dest', chunk_size )

			# Block 8 - Set the decoded variable to the byte pointed to by the source variable
			@machine.create_block_primitive( 'block8', 'load', 'decoded', 'source', chunk_size )

			# Block 9 - Xor the decoded variable with the encoded variable
			@machine.create_block_primitive( 'block9', 'xor', 'decoded', 'encoded' )

			# Block 10 - store the newly decoded byte
			@machine.create_block_primitive( 'block10', 'store', 'source', 'decoded', chunk_size )

			# Block 11 - Increment the source variable by one
			@machine.create_block_primitive( 'block11', 'add', 'source', chunk_size )

			# Block 12 - Jump back up to the outer_loop block while the counter variable > 0
			@machine.create_block_primitive( 'block12', 'loop', 'counter', 'block6' )

			# Try to generate the decoder stub...
			decoder = @machine.generate

			if( not decoder )
				raise RuntimeError, "Unable to generate decoder stub."
			end

			decoder
		end

		#
		# Compute the seed block which will successfully decode all proceeding encoded
		# blocks while ensuring the encoded blocks do not contain any badchars.
		#
		def compute_seed( blocks_in, block_size, block_padding, badchars )
			seed       = []
			redo_bytes = []

			0.upto( block_size-1 ) do | index |

				seed_bytes = (0..255).sort_by do
					rand()
				end

				seed_bytes.each do | seed_byte |

					next if( badchars.include?( seed_byte ) )

					success = true

					previous_byte = seed_byte

					if( redo_bytes.length < 256 )
						redo_bytes = (0..255).sort_by do
							rand()
						end
					end

					blocks_in.each do | block |

						decoded_byte = block[ index ]

						encoded_byte = previous_byte ^ decoded_byte

						if( badchars.include?( encoded_byte ) )
							# the padding bytes we added earlier can be changed if they are causing us to fail.
							if( block == blocks_in.last and index >= (block_size-block_padding) )
								if( redo_bytes.empty? )
									success = false
									break
								end
								block[ index ] = redo_bytes.shift
								redo
							end

							success = false
							break
						end

						previous_byte = encoded_byte
					end

					if( success )
						seed << seed_byte
						break
					end
				end

			end

			if( seed.length == block_size )
				return seed
			end

			return nil
		end

		#
		# Compute the next encoded block by xoring the previous
		# encoded block with the next decoded block.
		#
		def compute_block( encoded, decoded )
			block = []
			0.upto( encoded.length-1 ) do | index |
				block << ( encoded[ index ] ^ decoded[ index ] )
			end
			return block
		end

	end

end

end
