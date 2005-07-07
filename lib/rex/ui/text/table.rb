module Rex
module Ui
module Text

###
#
# Table
# -----
#
# Prints text in a tablized format.  Pretty lame at the moment, but 
# whatever.
#
###
class Table

	def initialize(opts = {})
		self.columns  = opts['Columns'] || []
		self.rows     = opts['Rows']    || []

		self.width    = opts['Width']   || 80
		self.indent   = opts['Indent']  || 0
		self.cellpad  = opts['CellPad'] || 2
		self.colprops = []

		self.columns.length.times { |idx|
			self.colprops[idx] = {}
			self.colprops[idx]['MaxWidth'] = self.columns[idx].length
		}

	end

	#
	# Converts table contents to a string
	# 
	def to_s
		str  = columns_to_s || ''
		str += hr_to_s || ''
		
		rows.each { |row|
			if (is_hr(row))
				str += hr_to_s
			else
				str += row_to_s(row)
			end
		}

		return str
	end

	#
	# Prints the contents of the table
	#
	def print
		puts to_s
	end

	#
	# Adds a row using the supplied fields
	#
	def <<(fields)
		add_row(fields)
	end

	#
	# Adds a row with the supplied fields
	#
	def add_row(fields = [])
		fields.each_with_index { |field, idx|
			if (colprops[idx]['MaxWidth'] < field.length)
				colprops[idx]['MaxWidth'] = field.length
			end
		}

		rows << fields	
	end

	#
	# Adds a horizontal line
	#
	def add_hr
		rows << '__hr__'
	end

	alias p print

	attr_accessor :columns, :rows, :colprops
	attr_accessor :width, :indent, :cellpad

protected

	#
	# :nodoc:
	#
	# Defaults cell widths and alignments
	#
	def defaults
		self.columns.length.times { |idx|
		}
	end

	#
	# :nodoc:
	#
	# Checks to see if the row is an hr
	#
	def is_hr(row)
		return ((row.kind_of?(String)) && (row == '__hr__'))
	end

	#
	# :nodoc:
	#
	# Converts the columns to a string
	#
	def columns_to_s
		nameline = ' ' * indent
		barline  = nameline

		columns.each_with_index { |col,idx|
			nameline += col + pad(' ', col, idx)
			barline  += ('-' * colprops[idx]['MaxWidth']) + (' ' * cellpad)
		}

		return "#{nameline}\n#{barline}"
	end

	#
	# :nodoc:
	#
	# Converts an hr to a string
	#
	def hr_to_s
		return "\n"
	end

	#
	# :nodoc:
	#
	# Converts a row to a string
	#
	def row_to_s(row)
		line = ' ' * indent

		row.each_with_index { |cell, idx|
			line += cell + pad(' ', cell, idx)
		}

		return line + "\n"
	end

	#
	# :nodoc:
	#
	# Pads out with the supplied character for the remainder of the space given
	# some text and a column index.
	#
	def pad(chr, buf, colidx, use_cell_pad = true)
		remainder = colprops[colidx]['MaxWidth'] - buf.length
		val       = chr * remainder;

		if (use_cell_pad)
			val += ' ' * cellpad
		end

		return val
	end

end

end
end
end
