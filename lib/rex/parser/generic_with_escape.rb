# -*- coding: binary -*-
module Rex
module Parser


class GenericWithEscapeParser

	attr_reader :items
	attr_reader :sep
	attr_reader :esc
	attr_accessor :data

	def initialize(data, separator = ';', escape = '\\')
		@data = data
		@sep = Regexp.escape(separator)
		@esc = Regexp.escape(escape)
		@items = []
	end

	def sep=(separator)
		@sep = Regexp.escape(separator)
	end

	def esc=(escape)
		@esc = Regexp.escape(escape)
	end

	def parse
		# FYI, look-behind assertions are only available in Ruby 1.9.x, otherwise we wouldn't much need this
		temp_items = @data.split(/#{@sep}/) || []
		# now we test for items that may have been escaped
		# need to account for items that end with \\ but that weren't just items ending in \\ but not escapes
		# e.g. we want to catch this stuff\\;stuff, but not stuff\\ ;stuff
		first_half = nil
		temp_items.each do |item|
			if first_half # then this is the second half
				@items << first_half.strip+item.strip
				first_half = nil
			elsif item =~ /#{@esc}$/
				#then this was escaped and the next item should be merged w/this one
				first_half = item.sub(/#{@esc}$/,';')
			else # this is just a normal item
				@items << item.strip
			end
		end
		@items
	end

end # end class

end
end

