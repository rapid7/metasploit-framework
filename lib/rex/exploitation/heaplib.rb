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
	end
end

end
end