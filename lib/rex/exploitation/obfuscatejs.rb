module Rex
module Exploitation

#
# Obfuscates javascript in various ways
#
class ObfuscateJS
	attr_reader :opts

	#
	# Obfuscates a javascript string.  
	#
	# Options are 'Symbols', described below, and 'Strings', a boolean
	# which specifies whether strings within the javascript should be 
	# mucked with (defaults to false).
	#
	# The 'Symbols' argument should have the following format:
	#
	# {
	#    'Variables'  => [ 'var1', ... ],
	#    'Methods'    => [ 'method1', ... ],
	#    'Namespaces' => [ 'n', ... ],
	#    'Classes'    => [ { 'Namespace' => 'n', 'Class' => 'y'}, ... ]
	# }
	#
	# Make sure you order your methods, classes, and namespaces by most
	# specific to least specific to prevent partial substitution.  For
	# instance, if you have two methods (joe and joeBob), you should place
	# joeBob before joe because it is more specific and will be globally
	# replaced before joe is replaced.
	#
	# A simple example follows:
	#
	# <code>
	# js = ObfuscateJS.new <<ENDJS
	#     function say_hi() {
	#         var foo = "Hello, world";
	#         document.writeln(foo);
	#     }
	# ENDJS
	# js.obfuscate(
	#     'Symbols' => { 
	#	       'Variables' => [ 'foo' ],
	#	       'Methods'   => [ 'say_hi' ] 
	#	  }
	#     'Strings' => true
	# )
	# </code>
	#
	# which should generate something like the following:
	#
	# <code>
	# function oJaDYRzFOyJVQCOHk() { var cLprVG = "\x48\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64"; document.writeln(cLprVG); }
	# </code>
	#
	# String obfuscation tries to deal with escaped quotes within strings but
	# won't catch things like 
	#     "\\"
	# so be careful.
	#
	def self.obfuscate(js, opts = {})
		ObfuscateJS.new(js).obfuscate(opts)
	end

	#
	# Initialize an instance of the obfuscator
	#
	def initialize(js, opts = {})
		@js      = js
		@dynsym  = {}
		@opts    = {
			'Symbols' => {
				'Variables'=>[],
				'Methods'=>[],
				'Namespaces'=>[],
				'Classes'=>[]
			},
			'Strings'=>false
		}
		@done = false
		update_opts(opts) if (opts.length > 0)
	end

	def update_opts(opts)
		if (opts.nil? or opts.length < 1)
			return
		end
		if (@opts['Symbols'] && opts['Symbols'])
			['Variables', 'Methods', 'Namespaces', 'Classes'].each { |k|
				if (@opts['Symbols'][k] && opts['Symbols'][k])
					opts['Symbols'][k].each { |s|
						if (not @opts['Symbols'][k].include? s)
							@opts['Symbols'][k].push(s)
						end
					}
				elsif (opts['Symbols'][k])
					@opts['Symbols'][k] = opts['Symbols'][k] 
				end
			}
		elsif opts['Symbols']
			@opts['Symbols'] = opts['Symbols']
		end
		@opts['Strings'] ||= opts['Strings']
	end

	#
	# Returns the dynamic symbol associated with the supplied symbol name
	#
	# If obfuscation has not yet been performed (i.e. obfuscate() has not been
	# called), then this method simply returns its argument
	#
	def sym(name)
		@dynsym[name] || name
	end

	#
	# Obfuscates the javascript string passed to the constructor
	#
	def obfuscate(opts = {})
		return @js if (@done)
		@done = true

		# Remove our comments
		remove_comments
		
		update_opts(opts)

		#$stderr.puts @opts.inspect
		if (@opts['Strings'])
			obfuscate_strings()

			# Full space randomization does not work for javascript -- despite
			# claims that space is irrelavent, newlines break things.  Instead,
			# use only space (0x20) and tab (0x09).

			@js = Rex::Text.compress(@js)
			@js.gsub!(/\s+/) { |s|
				len = rand(50)+2
				set = "\x09\x20"
				buf = ''
				while (buf.length < len)
					buf << set[rand(set.length)].chr
				end
				
				buf
			}
		end
		# Globally replace symbols
		replace_symbols(@opts['Symbols']) if @opts['Symbols']

		return @js
	end

	#
	# Returns the replaced javascript string
	#
	def to_s
		@js
	end
	alias :to_str :to_s

protected
	attr_accessor :done

	#
	# Get rid of both single-line C++ style comments and multiline C style comments.
	#
	# Note: embedded comments (e.g.: "/*/**/*/") will break this,
	# but they also break real javascript engines so I don't care.
	#
	def remove_comments
		@js.gsub!(%r{//.*$}, '')
		@js.gsub!(%r{/\*.*?\*/}m, '')
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

	#
	# Change each string into some javascript that will generate that string
	#
	# There are a couple of caveats to using string obfuscation:
	#   * it tries to deal with escaped quotes within strings but won't catch
	#     things like: "\\"
	#   * multiple calls to this method are very likely to result in incorrect
	#     code.  DON'T CALL THIS METHOD MORE THAN ONCE
	# so be careful.
	#
	def obfuscate_strings()
		@js.gsub!(/".*?[^\\]"|'.*?[^\\]'/) { |str|
			str = str[1, str.length-2]
			case (rand(3))
			when 0
				buf = '"' + Rex::Text.to_hex(str) + '"'
			when 1
				 buf = "unescape(\"" + Rex::Text.to_hex(str, "%") + "\")" 
			when 2
				buf = "String.fromCharCode(" 
				str.each_byte { |c| 
					if (0 == rand(2))
						buf << " %i,"%(c)
					else
						buf << " 0x%0.2x,"%(c) 
					end
				}
				buf = buf[0,buf.length-1] + " )" 
			end
			buf
		}
		@js
	end

end

end
end