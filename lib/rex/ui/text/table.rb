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
    self.scterm   = /#{opts['SearchTerm']}/mi if opts['SearchTerm']

    self.sort_index  = opts['SortIndex'] || 0
    self.sort_order  = opts['SortOrder'] || :forward

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
        str << row_to_s(row) if row_visible(row)
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
      next if is_hr(row) || !row_visible(row)
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
      # Remove whitespace and ensure String format
      field = field.to_s.strip
      if (colprops[idx]['MaxWidth'] < field.to_s.length)
        old = colprops[idx]['MaxWidth']
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
  def sort_rows(index = sort_index, order = sort_order)
    return if index == -1
    return unless rows
    rows.sort! do |a,b|
      if a[index].nil?
        cmp = -1
      elsif b[index].nil?
        cmp = 1
      elsif Rex::Socket.dotted_ip?(a[index]) and Rex::Socket.dotted_ip?(b[index])
        cmp = Rex::Socket::addr_atoi(a[index]) <=> Rex::Socket::addr_atoi(b[index])
      elsif a[index] =~ /^[0-9]+$/ and b[index] =~ /^[0-9]+$/
        cmp = a[index].to_i <=> b[index].to_i
      else
        cmp = a[index] <=> b[index] # assumes otherwise comparable.
      end
      order == :forward ? cmp : -cmp
    end
  end

  #
  # Adds a horizontal line.
  #
  def add_hr
    rows << '__hr__'
  end

  #
  # Returns new sub-table with headers and rows maching column names submitted
  #
  #
  # Flips table 90 degrees left
  #
  def drop_left
    tbl = self.class.new(
      'Columns' => Array.new(self.rows.count+1,'  '),
      'Header' => self.header,
      'Indent' => self.indent)
    (self.columns.count+1).times do |ti|
      row = self.rows.map {|r| r[ti]}.unshift(self.columns[ti]).flatten
      # insert our col|row break. kind of hackish
      row[1] = "| #{row[1]}" unless row.all? {|e| e.nil? || e.empty?}
      tbl << row
    end
    return tbl
  end

  #
  # Build table from CSV dump
  #
  def self.new_from_csv(csv)
    # Read in or keep data, get CSV or die
    if csv.is_a?(String)
      csv = File.file?(csv) ? CSV.read(csv) : CSV.parse(csv)
    end
    # Adjust for skew
    if csv.first == ["Keys", "Values"]
      csv.shift # drop marker
      cols = []
      rows = []
      csv.each do |row|
        cols << row.shift
        rows << row
      end
      tbl = self.new('Columns' => cols)
      rows.in_groups_of(cols.count) {|r| tbl << r.flatten}
    else
      tbl = self.new('Columns' => csv.shift)
      while !csv.empty? do
        tbl << csv.shift
      end
    end
    return tbl
  end

  def [](*col_names)
    tbl = self.class.new('Indent' => self.indent,
                         'Header' => self.header,
                         'Columns' => col_names)
    indexes = []

    col_names.each do |col_name|
      index = self.columns.index(col_name)
      raise RuntimeError, "Invalid column name #{col_name}" if index.nil?
      indexes << index
    end

    self.rows.each do |old_row|
      new_row = []
      indexes.map {|i| new_row << old_row[i]}
      tbl << new_row
    end

    return tbl
  end


  alias p print

  attr_accessor :header, :headeri # :nodoc:
  attr_accessor :columns, :rows, :colprops # :nodoc:
  attr_accessor :width, :indent, :cellpad # :nodoc:
  attr_accessor :prefix, :postfix # :nodoc:
  attr_accessor :sort_index, :sort_order, :scterm # :nodoc:

protected

  #
  # Returns if a row should be visible or not
  #
  def row_visible(row)
    return true if self.scterm.nil?
    row_to_s(row).match(self.scterm)
  end

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
        # This produces clean to_s output without truncation
        # Preserves full string in cells for to_csv output
        padding = pad(' ', last_col, last_idx)
        nameline << padding
        remainder = padding.length - cellpad
        remainder = 0 if remainder < 0
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
      if (idx != 0)
        line << pad(' ', last_cell.to_s, last_idx)
      end
      # Limit wide cells
      if colprops[idx]['MaxChar']
        last_cell = cell.to_s[0..colprops[idx]['MaxChar'].to_i]
        line << last_cell
      else
        line << cell.to_s
        last_cell = cell
      end
      last_idx = idx
    }

    return line + "\n"
  end

  #
  # Pads out with the supplied character for the remainder of the space given
  # some text and a column index.
  #
  def pad(chr, buf, colidx, use_cell_pad = true) # :nodoc:
    # Ensure we pad the minimum required amount
    max = colprops[colidx]['MaxChar'] || colprops[colidx]['MaxWidth']
    max = colprops[colidx]['MaxWidth'] if max.to_i > colprops[colidx]['MaxWidth'].to_i
    remainder = max - buf.length
    remainder = 0 if remainder < 0
    val       = chr * remainder

    if (use_cell_pad)
      val << ' ' * cellpad
    end

    return val
  end


end

end
end
end
