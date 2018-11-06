# coding: utf-8

require 'ttfunk'

class PDF::Reader

  # Font descriptors are outlined in Section 9.8, PDF 32000-1:2008, pp 281-288
  class FontDescriptor

    attr_reader :font_name, :font_family, :font_stretch, :font_weight,
                :font_bounding_box, :cap_height, :ascent, :descent, :leading,
                :avg_width, :max_width, :missing_width, :italic_angle, :stem_v,
                :x_height, :font_flags

    def initialize(ohash, fd_hash)
      @ascent                = ohash.object(fd_hash[:Ascent])    || 0
      @descent               = ohash.object(fd_hash[:Descent])   || 0
      @missing_width         = ohash.object(fd_hash[:MissingWidth]) || 0
      @font_bounding_box     = ohash.object(fd_hash[:FontBBox])  || [0,0,0,0]
      @avg_width             = ohash.object(fd_hash[:AvgWidth])  || 0
      @cap_height            = ohash.object(fd_hash[:CapHeight]) || 0
      @font_flags            = ohash.object(fd_hash[:Flags])     || 0
      @italic_angle          = ohash.object(fd_hash[:ItalicAngle])
      @font_name             = ohash.object(fd_hash[:FontName]).to_s
      @leading               = ohash.object(fd_hash[:Leading])   || 0
      @max_width             = ohash.object(fd_hash[:MaxWidth])  || 0
      @stem_v                = ohash.object(fd_hash[:StemV])
      @x_height              = ohash.object(fd_hash[:XHeight])
      @font_stretch          = ohash.object(fd_hash[:FontStretch]) || :Normal
      @font_weight           = ohash.object(fd_hash[:FontWeight])  || 400
      @font_family           = ohash.object(fd_hash[:FontFamily])

      # A FontDescriptor may have an embedded font program in FontFile
      # (Type 1 Font Program), FontFile2 (TrueType font program), or
      # FontFile3 (Other font program as defined by Subtype entry)
      # Subtype entries:
      # 1) Type1C:        Type 1 Font Program in Compact Font Format
      # 2) CIDFontType0C: Type 0 Font Program in Compact Font Format
      # 3) OpenType:      OpenType Font Program
      # see Section 9.9, PDF 32000-1:2008, pp 288-292
      @font_program_stream = ohash.object(fd_hash[:FontFile2])
      #TODO handle FontFile and FontFile3

      @is_ttf = true if @font_program_stream
    end

    def glyph_width(char_code)
      if @is_ttf
        if ttf_program_stream.cmap.unicode.length > 0
          glyph_id = ttf_program_stream.cmap.unicode.first[char_code]
        else
          glyph_id = char_code
        end
        char_metric = ttf_program_stream.horizontal_metrics.metrics[glyph_id]
        if char_metric
          return char_metric.advance_width
        end
      end
    end

    # PDF states that a glyph is 1000 units wide, true type doesn't enforce
    # any behavior, but uses units/em to define how wide the 'M' is (the widest letter)
    def glyph_to_pdf_scale_factor
      if @is_ttf
        @glyph_to_pdf_sf ||= (1.0 / ttf_program_stream.header.units_per_em) * 1000.0
      else
        @glyph_to_pdf_sf ||= 1.0
      end
      @glyph_to_pdf_sf
    end

    private

    def ttf_program_stream
      @ttf_program_stream ||= TTFunk::File.new(@font_program_stream.unfiltered_data)
    end
  end

end
