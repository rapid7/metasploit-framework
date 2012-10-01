require 'rex/text'
require 'rexml/document'


module Rex
module Exploitation

###
#
# This class provides methods to access the ROP database, in order to generate
# a ROP-compatible payload on the fly.
#
###
class RopDb
	def initialize
		f = open(File.join(File.dirname(__FILE__), '../../../data/ropdb', 'ropdb.xml'))
		@xml = REXML::Document.new(f.read)
		f.close
	end

	public


	#
	# Returns true if a ROP chain is available, otherwise false
	#
	def has_rop?(rop)
		@xml.elements.each("db/rop") { |e|
			name = e.attributes['name']
			return true if name =~ /#{rop}/i
		}
		return false
	end

	#
	# Returns an array of ROP gadgets. Each gadget can either be an offset, or a value (symbol or
	# some integer).  When the value is a symbol, it can be one of these: :nop, :junk, :size.
	# Note if no RoP is found, it returns an empry array.
	# Arguments:
	# rop_name - name of the ROP chain.
	# opts     - A hash of optional arguments:
	#            'target' - A regex string search against the compatibility list.
	#            'base'   - Specify a different base for the ROP gadgets.
	#
	def select_rop(rop, opts={})
		target = opts['target'] || ''
		base   = opts['base']   || nil

		gadgets = []
		@xml.elements.each("db/rop") { |e|
			name = e.attributes['name']
			next if name !~ /^#{rop}$/i
			next if not has_target?(e, target)

			if not base
				default = e.elements['gadgets'].attributes['base'].scan(/^0x([0-9a-f]+)$/i).flatten[0]
				base = default.to_i(16)
			end

			e.elements.each('gadgets/gadget') { |g|
				offset = g.attributes['offset']
				value  = g.attributes['value']

				if offset
					addr = offset.scan(/^0x([0-9a-f]+)$/i).flatten[0]
					gadgets << (base + addr.to_i(16))
				elsif value
					case value
					when 'nop'
						gadgets << :nop
					when 'junk'
						gadgets << :junk
					when 'size'
						gadgets << :size
					when 'size_negate'
						gadgets << :size_negate
					else
						gadgets << value.to_i(16)
					end
				else
					raise RuntimeError, "Missing offset or value attribute in '#{name}'"
				end
			}
		}
		gadgets = gadgets.flatten
		return gadgets
	end


	#
	# Returns a payload with the user-supplied stack-pivot, a ROP chain,
	# and then shellcode.
	# Arguments:
	# rop     - Name of the ROP chain
	# payload - Payload in binary
	# opts    - A hash of optional arguments:
	#           'nop'      - Used to generate nops with generate_sled()
	#           'badchars' - Used in a junk gadget
	#           'pivot'    - Stack pivot in binary
	#           'target'   - A regex string search against the compatibility list.
	#           'base'     - Specify a different base for the ROP gadgets.
	#
	def generate_rop_payload(rop, payload, opts={})
		nop      = opts['nop']      || nil
		badchars = opts['badchars'] || ''
		pivot    = opts['pivot']    || ''
		target   = opts['target']   || ''
		base     = opts['base']     || nil

		rop = select_rop(rop, {'target'=>target, 'base'=>base})
		# Replace the reserved words with actual gadgets
		rop = rop.map {|e|
			if e == :nop
				sled = (nop) ? nop.generate_sled(4, badchars).unpack("V*")[0] : 0x90909090
			elsif e == :junk
				Rex::Text.rand_text(4, badchars).unpack("V")[0].to_i
			elsif e == :size
				payload.length
			elsif e == :size_negate
				0xffffffff - payload.length + 1
			else
				e
			end
		}.pack("V*")

		raise RuntimeError, "No ROP chain generated successfully" if rop.empty?

		return pivot + rop + payload
	end

	private


	#
	# Checks if a ROP chain is compatible
	#
	def has_target?(rop, target)
		rop.elements.each('compatibility/target') { |t|
			return true if t.text =~ /#{target}/i
		}
		return false
	end
end

end
end