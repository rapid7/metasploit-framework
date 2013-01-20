# -*- coding: binary -*-
module Rex
module Parser

#
# The GenericWithEscape class is a parser for parsing generic string data into an array
# using +separator+, which defaults to ';', to delimit the data and the +escape+ char, which
# defaults to '\', to escape the separator thus skipping that instance of the delimiter
#
class GenericWithEscape

	attr_reader		:items
	attr_reader		:sep
	attr_reader		:esc
	attr_accessor	:data

	#
	# Initializes the parser
	#
	# @param data [String] The data to be parsed
	# @param separator [String] The separator used to delimit the data
	# @param escape [String] The escape character used to escape +separator+
	# @return [Void]
	def initialize(data, separator = ';', escape = '\\')
		# keep in mind that \ is a special char in ruby too, so '\\' becomes \
		@data = data
		@sep = Regexp.escape(separator)
		@esc = Regexp.escape(escape)
		@items = []
	end

	#
	# Assigns the +separator+
	#
	# @param separator [String] the separator used to delimit the data
	# @return [Void]
	def sep=(separator)
		@sep = Regexp.escape(separator)
	end

	#
	# Assigns the +escape+ character
	#
	# @param escape [String] the escape character used to escape +separator+
	# @return [Void]
	def esc=(escape)
		@esc = Regexp.escape(escape)
	end

	#
	# Perform the parsing
	#
	# @return [Array<String>] The parsed items
	def parse
		# FYI, look-behind assertions are only available in Ruby 1.9.x, otherwise we wouldn't much need this
		temp_items = @data.split(/#{@sep}/) || []
		# now we test for items that may have been escaped
		# need to account for items that end with \ but that weren't just items ending in \ but not escapes
		# e.g. we want to catch this stuff\;stuff, but not stuff\ ;stuff and not stuff\\;stuff
		first_part = ""
		escaped = false
		temp_items.each do |item|
			# the sep was escaped if odd number of escape chars at end, usually 1
			# and the next item should be merged w/current one
			escaped = item_is_escaping_the_separator?(item)
			if escaped
				first_part += item.sub(/#{@esc}$/,"#{@sep}")
			else
				unless first_part.empty?
					@items << first_part+item.rstrip
					first_part = ""
				else # this is just a normal item
					@items << item.strip
				end
			end
		end
		@items
	end
	protected
	def item_is_escaping_the_separator?(item)
		return true if (item =~ /#{@esc}+$/ and not $&.count(@esc).even?)
		return false
	end
end # end class

end
end

