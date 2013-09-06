# -*- coding: binary -*-
require 'rex/ui'
require 'rex/socket'

module Rex
module Ui
module Text

###
#
# Prints text in a tablized format.  Pretty lame at the moment, but
# whatever.
#
###
class Table

  #
  # Initializes a text table instance using the supplied properties.  The
  # Table class supports the following hash attributes:
  #
  # Header
  #
  #	The string to display as a heading above the table.  If none is
  #	specified, no header will be displayed.
  #
  # HeaderIndent
  #
  # 	The amount of space to indent the header.  The default is zero.
  #
  # Columns
  #
  # 	The array of columns that will exist within the table.
  #
  # Rows
  #
  # 	The array of rows that will exist.
  #
  # Width
  #
  # 	The maximum width of the table in characters.
  #
  # Indent
  #
  # 	The number of characters to indent the table.
  #
  # CellPad
  #
  # 	The number of characters to put between each horizontal cell.
  #
  # Prefix
  #
  # 	The text to prefix before the table.
  #
  # Postfix
  #
  # 	The text to affix to the end of the table.
  #
  # Sortindex
  #
  #	The column to sort the table on, -1 disables sorting.
  #
  def initialize(opts = {})
    self.header   = opts['Header']
    self.headeri  = opts['HeaderIndent'] || 0
    self.columns  = opts['Columns'] || []
    # updated below if we got a "Rows" option
    self.rows     = []

    self.width    = opts['Width']   || 80
    self.indent   = opts['Indent']  || 0
    self.cellpad  = opts['CellPad'] || 2
    self.prefix   = opts['Prefix']  || ''
    self.postfix  = opts['Postfix'] || ''
    self.colprops = []

    self.sort_index  = opts['SortIndex'] || 0

    # Default column properties
    self.columns.length.times { |idx|
      self.colprops[idx] = {}
      self.colprops[idx]['MaxWidth'] = self.columns[idx].length
    }

    # ensure all our internal state gets updated with the given rows by
    # using add_row instead of just adding them to self.rows.  See #3825.
    opts['Rows'].each { |row| add_row(row) } if opts['Rows']

    # Merge in options
    if (opts['ColProps'])
      opts['ColProps'].each_key { |col|
        idx = self.columns.index(col)

        if (idx)
          self.colprops[idx].merge!(opts['ColProps'][col])
        end
      }
    end

  end

  #
  # Converts table contents to a string.
  #
  def to_s
    str  = prefix.dup
    str << header_to_s || ''
    str << columns_to_s || ''
    str << hr_to_s || ''

    sort_rows
    rows.each { |row|
      if (is_hr(row))
        str << hr_to_s
      else
        str << row_to_s(row)
      end
    }

    str << postfix

    return str
  end

  #
  # Converts table contents to a csv
  #
  def to_csv
    str = ''
    str << ( columns.join(",") + "\n" )
    rows.each { |row|
      next if is_hr(row)
      str << ( row.map{|x|
        x = x.to_s

        x.gsub(/[\r\n]/, ' ').gsub(/\s+/, ' ').gsub('"', '""')
      }.map{|x| "\"#{x}\"" }.join(",") + "\n" )
    }
    str
  end

  #
  #
  # Returns the header string.
  #
  def header_to_s # :nodoc:
    if (header)
      pad = " " * headeri

      return pad + header + "\n" + pad + "=" * header.length + "\n\n"
    end

    return ''
  end

  #
  # Prints the contents of the table.
  #
  def print
    puts to_s
  end

  #
  # Adds a row using the supplied fields.
  #
  def <<(fields)
    add_row(fields)
  end

  #
  # Adds a row with the supplied fields.
  #
  def add_row(fields = [])
    if fields.length != self.columns.length
      raise RuntimeError, 'Invalid number of columns!'
    end
    fields.each_with_index { |field, idx|
      if (colprops[idx]['MaxWidth'] < field.to_s.length)
        colprops[idx]['MaxWidth'] = field.to_s.length
      end
    }

    rows << fields
  end

  #
  # Sorts the rows based on the supplied index of sub-arrays
  # If the supplied index is an IPv4 address, handle it differently, but
  # avoid actually resolving domain names.
  #
  def sort_rows(index=sort_index)
    return if index == -1
    return unless rows
    rows.sort! do |a,b|
      if a[index].nil?
        -1
      elsif b[index].nil?
        1
      elsif Rex::Socket.dotted_ip?(a[index]) and Rex::Socket.dotted_ip?(b[index])
        Rex::Socket::addr_atoi(a[index]) <=> Rex::Socket::addr_atoi(b[index])
      elsif a[index] =~ /^[0-9]+$/ and b[index] =~ /^[0-9]+$/
        a[index].to_i <=> b[index].to_i
      else
        a[index] <=> b[index] # assumes otherwise comparable.
      end
    end
  end

  #
  # Adds a horizontal line.
  #
  def add_hr
    rows << '__hr__'
  end

  alias p print

  attr_accessor :header, :headeri # :nodoc:
  attr_accessor :columns, :rows, :colprops # :nodoc:
  attr_accessor :width, :indent, :cellpad # :nodoc:
  attr_accessor :prefix, :postfix # :nodoc:
  attr_accessor :sort_index # :nodoc:

protected

  #
  # Defaults cell widths and alignments.
  #
  def defaults # :nodoc:
    self.columns.length.times { |idx|
    }
  end

  #
  # Checks to see if the row is an hr.
  #
  def is_hr(row) # :nodoc:
    return ((row.kind_of?(String)) && (row == '__hr__'))
  end

  #
  # Converts the columns to a string.
  #
  def columns_to_s # :nodoc:
    nameline = ' ' * indent
    barline  = nameline.dup
    last_col = nil
    last_idx = nil
    columns.each_with_index { |col,idx|
      if (last_col)
        nameline << pad(' ', last_col, last_idx)

        remainder = colprops[last_idx]['MaxWidth'] - last_col.length
      if (remainder < 0)
        remainder = 0
      end
        barline << (' ' * (cellpad + remainder))
      end
      nameline << col
      barline << ('-' * col.length)

      last_col = col
      last_idx = idx
    }

    return "#{nameline}\n#{barline}"
  end

  #
  # Converts an hr to a string.
  #
  def hr_to_s # :nodoc:
    return "\n"
  end

  #
  # Converts a row to a string.
  #
  def row_to_s(row) # :nodoc:
    line = ' ' * indent
    last_cell = nil
    last_idx = nil
    row.each_with_index { |cell, idx|
      if (last_cell)
        line << pad(' ', last_cell.to_s, last_idx)
      end
      line << cell.to_s
      # line << pad(' ', cell.to_s, idx)
      last_cell = cell
      last_idx = idx
    }

    return line + "\n"
  end

  #
  # Pads out with the supplied character for the remainder of the space given
  # some text and a column index.
  #
  def pad(chr, buf, colidx, use_cell_pad = true) # :nodoc:
    remainder = colprops[colidx]['MaxWidth'] - buf.length
    val       = chr * remainder;

    if (use_cell_pad)
      val << ' ' * cellpad
    end

    return val
  end


end

end
end
end
