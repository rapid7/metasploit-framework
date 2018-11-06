# coding: utf-8

################################################################################
#
# Copyright (C) 2008 James Healy (jimmy@deefa.com)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
################################################################################

require 'pdf/reader/width_calculator'

class PDF::Reader
  # Represents a single font PDF object and provides some useful methods
  # for extracting info. Mainly used for converting text to UTF-8.
  #
  class Font
    attr_accessor :subtype, :encoding, :descendantfonts, :tounicode
    attr_reader :widths, :first_char, :last_char, :basefont, :font_descriptor,
                :cid_widths, :cid_default_width

    def initialize(ohash, obj)
      @ohash = ohash
      @tounicode = nil

      extract_base_info(obj)
      extract_descriptor(obj)
      extract_descendants(obj)
      @width_calc = build_width_calculator

      @encoding ||= PDF::Reader::Encoding.new(:StandardEncoding)
    end

    def to_utf8(params)
      if @tounicode
        to_utf8_via_cmap(params)
      else
        to_utf8_via_encoding(params)
      end
    end

    def unpack(data)
      data.unpack(encoding.unpack)
    end

    # looks up the specified codepoint and returns a value that is in (pdf)
    # glyph space, which is 1000 glyph units = 1 text space unit
    def glyph_width(code_point)
      if code_point.is_a?(String)
        code_point = code_point.unpack(encoding.unpack).first
      end

      @cached_widths ||= {}
      @cached_widths[code_point] ||= @width_calc.glyph_width(code_point)
    end

    private

    def default_encoding(font_name)
      case font_name.to_s
      when "Symbol" then
        PDF::Reader::Encoding.new(:SymbolEncoding)
      when "ZapfDingbats" then
        PDF::Reader::Encoding.new(:ZapfDingbatsEncoding)
      else
        PDF::Reader::Encoding.new(:StandardEncoding)
      end
    end

    def build_width_calculator
      if @subtype == :Type0
        PDF::Reader::WidthCalculator::TypeZero.new(self)
      elsif @subtype == :Type1
        if @font_descriptor.nil?
          PDF::Reader::WidthCalculator::BuiltIn.new(self)
        else
          PDF::Reader::WidthCalculator::TypeOneOrThree .new(self)
        end
      elsif @subtype == :Type3
        PDF::Reader::WidthCalculator::TypeOneOrThree.new(self)
      elsif @subtype == :TrueType
        PDF::Reader::WidthCalculator::TrueType.new(self)
      elsif @subtype == :CIDFontType0 || @subtype == :CIDFontType2
        PDF::Reader::WidthCalculator::Composite.new(self)
      else
        PDF::Reader::WidthCalculator::TypeOneOrThree.new(self)
      end
    end

    def extract_base_info(obj)
      @subtype  = @ohash.object(obj[:Subtype])
      @basefont = @ohash.object(obj[:BaseFont])
      if @ohash.object(obj[:Encoding])
        @encoding = PDF::Reader::Encoding.new(@ohash.object(obj[:Encoding]))
      else
        @encoding = default_encoding(@basefont)
      end
      @widths   = @ohash.object(obj[:Widths]) || []
      @first_char = @ohash.object(obj[:FirstChar])
      @last_char = @ohash.object(obj[:LastChar])

      # CID Fonts are not required to have a W or DW entry, if they don't exist,
      # the default cid width = 1000, see Section 9.7.4.1 PDF 32000-1:2008 pp 269
      @cid_widths         = @ohash.object(obj[:W])  || []
      @cid_default_width  = @ohash.object(obj[:DW]) || 1000

      if obj[:ToUnicode]
        # ToUnicode is optional for Type1 and Type3
        stream = @ohash.object(obj[:ToUnicode])
        @tounicode = PDF::Reader::CMap.new(stream.unfiltered_data)
      end
    end

    def extract_descriptor(obj)
      if obj[:FontDescriptor]
        # create a font descriptor object if we can, in other words, unless this is
        # a CID Font
        fd = @ohash.object(obj[:FontDescriptor])
        @font_descriptor = PDF::Reader::FontDescriptor.new(@ohash, fd)
      else
        @font_descriptor = nil
      end
    end

    def extract_descendants(obj)
      return unless obj[:DescendantFonts]
      # per PDF 32000-1:2008 pp. 280 :DescendentFonts is:
      # A one-element array specifying the CIDFont dictionary that is the
      # descendant of this Type 0 font.
      descendants = @ohash.object(obj[:DescendantFonts])
      @descendantfonts = descendants.map { |desc|
        PDF::Reader::Font.new(@ohash, @ohash.object(desc))
      }
    end

    def to_utf8_via_cmap(params)
      case params
      when Integer
        [
          @tounicode.decode(params) || PDF::Reader::Encoding::UNKNOWN_CHAR
        ].flatten.pack("U*")
      when String
        params.unpack(encoding.unpack).map { |c|
          @tounicode.decode(c) || PDF::Reader::Encoding::UNKNOWN_CHAR
        }.flatten.pack("U*")
      when Array
        params.collect { |param| to_utf8_via_cmap(param) }
      else
        params
      end
    end

    def to_utf8_via_encoding(params)
      if encoding.kind_of?(String)
        raise UnsupportedFeatureError, "font encoding '#{encoding}' currently unsupported"
      end

      case params
      when Integer
        encoding.int_to_utf8_string(params)
      when String
        encoding.to_utf8(params)
      when Array
        params.collect { |param| to_utf8_via_encoding(param) }
      else
        params
      end
    end

  end
end
