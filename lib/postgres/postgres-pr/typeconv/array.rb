# -*- coding: binary -*-
require 'strscan'

module Postgres::Conversion

  def decode_array(str, delim=',', &conv_proc)
    delim = Regexp.escape(delim)
    buf = StringScanner.new(str)
    return parse_arr(buf, delim, &conv_proc)
  ensure
    raise ConversionError, "end of string expected (#{buf.rest})" unless buf.empty?
  end

  private

  def parse_arr(buf, delim, &conv_proc)
    # skip whitespace
    buf.skip(/\s*/)       

    raise ConversionError, "'{' expected" unless buf.get_byte == '{'

    elems = []
    unless buf.scan(/\}/) # array is not empty
      loop do
        # skip whitespace
        buf.skip(/\s+/)   

        elems <<
        if buf.check(/\{/)
          parse_arr(buf, delim, &conv_proc)
        else
          e = buf.scan(/("((\\.)|[^"])*"|\\.|[^\}#{ delim }])*/) || raise(ConversionError)
          if conv_proc then conv_proc.call(e) else e end
        end

        break if buf.scan(/\}/)
        break unless buf.scan(/#{ delim }/)
      end
    end

    # skip whitespace
    buf.skip(/\s*/)

    elems
  end

end
