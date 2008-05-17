module Rex
module Exploitation

#
# Obfuscates javascript in various ways
#
class ObfuscateJS
	STRINGS_SINGLE_QUOTES = 0
	STRINGS_DOUBLE_QUOTES = 1

	#
	# Obfuscates symbols found within a javascript string.  The symbols
	# argument should have the following format:
	#
	# {
	#    'Variables'  => [ 'var1', ... ],
	#    'Methods'    => [ 'method1', ... ],
	#    'Classes'    => [ { 'Namespace' => 'n', 'Class' => 'y'}, ... ],
	#    'Namespaces' => [ 'n', ... ]
	# }
	#
	# Make sure you order your methods, classes, and namespaces by most
	# specific to least specific to prevent partial substitution.  For
	# instance, if you have two methods (joe and joeBob), you should place
	# joeBob before joe because it is more specific and will be globally
	# replaced before joe is replaced.
	#
	def self.obfuscate(js, opts = {})
		ObfuscateJS.new(js).obfuscate(opts)
	end

	#
	# Initialize an instance of the obfuscator
	#
	def initialize(js)
		@js      = js
		@dynsym  = {}
	end

	#
	# Returns the dynamic symbol associated with the supplied symbol name
	#
	def sym(name)
		if (@dynsym[name])
			@dynsym[name]
		else 
			name
		end
	end

	#
	# Obfuscates the javascript string passed to the constructor
	#
	def obfuscate(opts = {})
		# Remove our comments
		remove_comments

		# Globally replace symbols
		replace_symbols(opts['Symbols']) if opts['Symbols']

		if (opts['Strings'])
			obfuscate_strings(opts['Strings'])
			# since there shouldn't be spaces in strings after the call to
			# obfuscate_strings, we can safely randomize the spaces as well
			@js = Rex::Text.compress(@js)
			@js = Rex::Text.randomize_space(@js)
		end


		@js
	end

	#
	# Returns the replaced javascript string
	#
	def to_s
		@js
	end

protected

	# Get rid of comments
	def remove_comments
		@js.gsub!(/(\/\/.+?\n)/m, '')
	end

	# Replace method, class, and namespace symbols found in the javascript
	# string
	def replace_symbols(symbols)
		taken = { }

		# Generate random symbol names
		[ 'Variables', 'Methods', 'Classes', 'Namespaces' ].each { |symtype|
			next if symbols[symtype].nil?
			symbols[symtype].each { |sym|
				dyn = Rex::Text.rand_text_alpha(rand(32)+1) until dyn and not taken.key?(dyn)
	
				taken[dyn] = true
			
				if symtype == 'Classes'
					full_sym = sym['Namespace'] + "." + sym['Class']
					@dynsym[full_sym] = dyn

					@js.gsub!(/#{full_sym}/) { |m|
						sym['Namespace'] + "." + dyn
					}
				else
					@dynsym[sym] = dyn

					@js.gsub!(/#{sym}/, dyn)
				end
			}
		}
	end

	def obfuscate_strings(type=STRINGS_SINGLE_QUOTES)
		if type == STRINGS_SINGLE_QUOTES
			regex = /'.*?[^\\]'/
		else 
			regex = /".*?[^\\]"/ 
		end
		return @js.gsub!(regex) { |str|
			str = str[1,str.length-2]

			case (rand(3))
			when 0
				buf = '"' + Rex::Text.to_hex(str) + '"'
			when 1
				buf = "unescape(\"" + Rex::Text.to_hex(str, "%") + "\")"
			else 
				buf = "String.fromCharCode("
				str.each_byte { |c|
					if (0 == rand(2))
						buf << "%i,"%(c)
					else
						buf << "0x%0.2x,"%(c)
					end
				}
				buf = buf[0,buf.length-1] + ")"
			end
			buf
		}
	end
end

end
end
