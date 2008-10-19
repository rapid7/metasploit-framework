require 'rex/text'
require 'rex/exploitation/obfuscatejs'

module Rex
module Exploitation

#
# Encapsulates the generation of the Alexander Sotirov's HeapLib javascript
# stub
#
class HeapLib

	#
	# The source file to load the javascript from
	#
	JavascriptFile = File.join(File.dirname(__FILE__), "heaplib.js.b64")

	#
	# The list of symbols found in the file.  This is used to dynamically
	# replace contents.
	#
	SymbolNames  = 
		{
			"Methods" =>
				[
					"vtable",
					"lookasideAddr",
					"lookaside",
					"freeList",
					"gc",
					"flushOleaut32",
					"freeOleaut32",
					"allocOleaut32",
					"free",
					"alloc",
					"addr",
					"hex",
					"round",
					"paddingStr",
					"padding",
					"debugBreak",
					"debugHeap",
					"debug",
				],
			"Classes" =>
				[	
					{ 'Namespace' => "heapLib", 'Class' => "ie" }
				],
			"Namespaces" =>
				[
					"heapLib"
				]
		}

	#
	# Initializes the heap library javascript
	#
	def initialize(custom_js = '')
		load_js(custom_js)
	end

	#
	# Return the replaced version of the javascript
	#
	def to_s
		@js
	end

protected

	#
	# Loads the raw javascript from the source file and strips out comments
	#
	def load_js(custom_js)
		
		# Grab the complete javascript
		File.open(JavascriptFile) { |f|
			@js = f.read
		}
		
		# Decode the text
		@js = Rex::Text.decode_base64(@js)
		
		# Append the real code
		@js += "\n" + custom_js
	
		# Obfuscate the javascript
		@js = ObfuscateJS.obfuscate(@js, 'Symbols' => SymbolNames)
	end

end

end
end