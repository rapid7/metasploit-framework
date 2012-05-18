module ChunkyPNG
  
  # Factory method to return a color value, based on the arguments given.
  #
  # @overload Color(r, g, b, a)
  #   @param (see ChunkyPNG::Color.rgba)
  #   @return [Integer] The rgba color value.
  #
  # @overload Color(r, g, b)
  #   @param (see ChunkyPNG::Color.rgb)
  #   @return [Integer] The rgb color value.
  #
  # @overload Color(hex_value, opacity = nil)
  #   @param (see ChunkyPNG::Color.from_hex)
  #   @return [Integer] The hex color value, with the opacity applied if one was given.
  #
  # @overload Color(color_name, opacity = nil)
  #   @param (see ChunkyPNG::Color.html_color)
  #   @return [Integer] The hex color value, with the opacity applied if one was given.
  #
  # @overload Color(color_value, opacity = nil)
  #   @param [Integer, :to_i] The color value.
  #   @return [Integer] The color value, with the opacity applied if one was given.
  #
  # @return [Integer] The determined color value as RGBA integer.
  # @raise [ArgumentError] if the arguments weren't understood as a color.
  # @see ChunkyPNG::Color
  # @see ChunkyPNG::Color.parse
  def self.Color(*args)
    case args.length
      when 1; ChunkyPNG::Color.parse(args.first)
      when 2; (ChunkyPNG::Color.parse(args.first) & 0xffffff00) | args[1].to_i
      when 3; ChunkyPNG::Color.rgb(*args)
      when 4; ChunkyPNG::Color.rgba(*args)
      else raise ArgumentError, "Don't know how to create a color from #{args.inspect}!"
    end
  end

  # The Color module defines methods for handling colors. Within the ChunkyPNG
  # library, the concepts of pixels and colors are both used, and they are
  # both represented by a Integer.
  #
  # Pixels/colors are represented in RGBA components. Each of the four
  # components is stored with a depth of 8 bits (maximum value = 255 =
  # {ChunkyPNG::Color::MAX}). Together, these components are stored in a 4-byte
  # Integer.
  #
  # A color will always be represented using these 4 components in memory.
  # When the image is encoded, a more suitable representation can be used
  # (e.g. rgb, grayscale, palette-based), for which several conversion methods
  # are provided in this module.
  module Color
    extend self

    # @return [Integer] The maximum value of each color component.
    MAX = 0xff
    
    # @private
    # @return [Regexp] The regexp to parse hex color values.
    HEX_COLOR_REGEXP  = /^(?:#|0x)?([0-9a-f]{6})([0-9a-f]{2})?$/i

    # @private
    # @return [Regexp] The regexp to parse named color values.
    HTML_COLOR_REGEXP = /^([a-z][a-z_ ]+[a-z])(?:\ ?\@\ ?(1\.0|0\.\d+))?$/i
    
    ####################################################################
    # CONSTRUCTING COLOR VALUES
    ####################################################################

    # Parses a color value given a numeric or string argument.
    #
    # It supports color numbers, colors in hex notation and named HTML colors.
    #
    # @param [Integer, String] The color value.
    # @return [Integer] The color value, with the opacity applied if one was given.
    def parse(source)
      return source if source.kind_of?(Integer)
      case source.to_s
        when /^\d+$/; source.to_s.to_i
        when ChunkyPNG::Color::HEX_COLOR_REGEXP;  ChunkyPNG::Color.from_hex(source.to_s)
        when ChunkyPNG::Color::HTML_COLOR_REGEXP; ChunkyPNG::Color.html_color(source.to_s)
        else raise ArgumentError, "Don't know how to create a color from #{source.inspect}!"
      end
    end

    # Creates a new color using an r, g, b triple and an alpha value.
    # @param [Integer] r The r-component (0-255)
    # @param [Integer] g The g-component (0-255)
    # @param [Integer] b The b-component (0-255)
    # @param [Integer] a The opacity (0-255)
    # @return [Integer] The newly constructed color value.
    def rgba(r, g, b, a)
      r << 24 | g << 16 | b << 8 | a
    end

    # Creates a new color using an r, g, b triple.
    # @param [Integer] r The r-component (0-255)
    # @param [Integer] g The g-component (0-255)
    # @param [Integer] b The b-component (0-255)
    # @return [Integer] The newly constructed color value.
    def rgb(r, g, b)
      r << 24 | g << 16 | b << 8 | 0xff
    end

    # Creates a new color using a grayscale teint.
    # @param [Integer] teint The grayscale teint (0-255), will be used as r, g, and b value.
    # @return [Integer] The newly constructed color value.
    def grayscale(teint)
      teint << 24 | teint << 16 | teint << 8 | 0xff
    end

    # Creates a new color using a grayscale teint and alpha value.
    # @param [Integer] teint The grayscale teint (0-255), will be used as r, g, and b value.
    # @param [Integer] a The opacity (0-255)
    # @return [Integer] The newly constructed color value.
    def grayscale_alpha(teint, a)
      teint << 24 | teint << 16 | teint << 8 | a
    end

    ####################################################################
    # COLOR IMPORTING
    ####################################################################

    # Creates a color by unpacking an rgb triple from a string.
    #
    # @param [String] stream The string to load the color from. It should be 
    #     at least 3 + pos bytes long.
    # @param [Integer] pos The position in the string to load the triple from.
    # @return [Integer] The newly constructed color value.
    def from_rgb_stream(stream, pos = 0)
      rgb(*stream.unpack("@#{pos}C3"))
    end

    # Creates a color by unpacking an rgba triple from a string
    #
    # @param [String] stream The string to load the color from. It should be 
    #      at least 4 + pos bytes long.
    # @param [Integer] pos The position in the string to load the triple from.
    # @return [Integer] The newly constructed color value.
    def from_rgba_stream(stream, pos = 0)
      rgba(*stream.unpack("@#{pos}C4"))
    end
    
    # Creates a color by converting it from a string in hex notation. 
    #
    # It supports colors with (#rrggbbaa) or without (#rrggbb) alpha channel.
    # Color strings may include the prefix "0x" or "#".
    #
    # @param [String] str The color in hex notation. @return [Integer] The
    #   converted color value.
    # @param [Integer] opacity The opacity value for the color. Overrides any
    #    opacity value given in the hex value if given.
    # @return [Integer] The color value.
    # @raise [ArgumentError] if the value given is not a hex color notation.
    def from_hex(hex_value, opacity = nil)
      if HEX_COLOR_REGEXP =~ hex_value
        base_color = $1.hex << 8
        opacity  ||= $2 ? $2.hex : 0xff
        base_color | opacity
      else 
        raise ArgumentError, "Not a valid hex color notation: #{hex_value.inspect}!"
      end
    end

    ####################################################################
    # PROPERTIES
    ####################################################################

    # Returns the red-component from the color value.
    #
    # @param [Integer] value The color value.
    # @return [Integer] A value between 0 and MAX.
    def r(value)
      (value & 0xff000000) >> 24
    end
    
    # Returns the green-component from the color value.
    #
    # @param [Integer] value The color value.
    # @return [Integer] A value between 0 and MAX.
    def g(value)
      (value & 0x00ff0000) >> 16
    end
    
    # Returns the blue-component from the color value.
    #
    # @param [Integer] value The color value.
    # @return [Integer] A value between 0 and MAX.
    def b(value)
      (value & 0x0000ff00) >> 8
    end
    
    # Returns the alpha channel value for the color value.
    #
    # @param [Integer] value The color value.
    # @return [Integer] A value between 0 and MAX.
    def a(value)
      value & 0x000000ff
    end
    
    # Returns true if this color is fully opaque.
    #
    # @param [Integer] value The color to test.
    # @return [true, false] True if the alpha channel equals MAX.
    def opaque?(value)
      a(value) == 0x000000ff
    end
    
    # Returns the opaque value of this color by removing the alpha channel.
    # @param [Integer] value The color to transform.
    # @return [Integer] The opaque color
    def opaque!(value)
      value | 0x000000ff
    end
    
    # Returns true if this color is fully transparent.
    #
    # @param [Integer] value The color to test.
    # @return [true, false] True if the r, g and b component are equal.
    def grayscale?(value)
      r(value) == b(value) && b(value) == g(value)
    end
    
    # Returns true if this color is fully transparent.
    #
    # @param [Integer] value The color to test.
    # @return [true, false] True if the alpha channel equals 0.
    def fully_transparent?(value)
      a(value) == 0x00000000
    end

    ####################################################################
    # ALPHA COMPOSITION
    ####################################################################

    # Multiplies two fractions using integer math, where the fractions are stored using an
    # integer between 0 and 255. This method is used as a helper method for compositing
    # colors using integer math.
    #
    # This is a quicker implementation of ((a * b) / 255.0).round.
    #
    # @param [Integer] a The first fraction.
    # @param [Integer] b The second fraction.
    # @return [Integer] The result of the multiplication.
    def int8_mult(a, b)
      t = a * b + 0x80
      ((t >> 8) + t) >> 8
    end

    # Composes two colors with an alpha channel using integer math.
    #
    # This version is faster than the version based on floating point math, so this
    # compositing function is used by default.
    #
    # @param [Integer] fg The foreground color.
    # @param [Integer] bg The foreground color.
    # @return [Integer] The composited color.
    # @see ChunkyPNG::Color#compose_precise
    def compose_quick(fg, bg)
      return fg if opaque?(fg) || fully_transparent?(bg)
      return bg if fully_transparent?(fg)
      
      a_com = int8_mult(0xff - a(fg), a(bg))
      new_r = int8_mult(a(fg), r(fg)) + int8_mult(a_com, r(bg))
      new_g = int8_mult(a(fg), g(fg)) + int8_mult(a_com, g(bg))
      new_b = int8_mult(a(fg), b(fg)) + int8_mult(a_com, b(bg))
      new_a = a(fg) + a_com
      rgba(new_r, new_g, new_b, new_a)
    end

    # Composes two colors with an alpha channel using floating point math.
    #
    # This method uses more precise floating point math, but this precision is lost
    # when the result is converted back to an integer. Because it is slower than
    # the version based on integer math, that version is preferred.
    #
    # @param [Integer] fg The foreground color.
    # @param [Integer] bg The foreground color.
    # @return [Integer] The composited color.
    # @see ChunkyPNG::Color#compose_quick
    def compose_precise(fg, bg)
      return fg if opaque?(fg) || fully_transparent?(bg)
      return bg if fully_transparent?(fg)
      
      fg_a  = a(fg).to_f / MAX
      bg_a  = a(bg).to_f / MAX
      a_com = (1.0 - fg_a) * bg_a

      new_r = (fg_a * r(fg) + a_com * r(bg)).round
      new_g = (fg_a * g(fg) + a_com * g(bg)).round
      new_b = (fg_a * b(fg) + a_com * b(bg)).round
      new_a = ((fg_a + a_com) * MAX).round
      rgba(new_r, new_g, new_b, new_a)
    end

    alias :compose :compose_quick
    
    # Blends the foreground and background color by taking the average of 
    # the components.
    #
    # @param [Integer] fg The foreground color.
    # @param [Integer] bg The foreground color.
    # @return [Integer] The blended color.
    def blend(fg, bg)
      (fg + bg) >> 1
    end

    # Interpolates the foreground and background colors by the given alpha value.
    # This also blends the alpha channels themselves.
    #
    # A blending factor of 255 will give entirely the foreground,
    # while a blending factor of 0 will give the background.
    #
    # @param [Integer] fg The foreground color.
    # @param [Integer] bg The background color.
    # @param [Integer] alpha The blending factor (fixed 8bit)
    # @param [Integer] The interpolated color.
    def interpolate_quick(fg, bg, alpha)
      return fg if alpha >= 255
      return bg if alpha <= 0
      
      alpha_com = 255 - alpha

      new_r = int8_mult(alpha, r(fg)) + int8_mult(alpha_com, r(bg))
      new_g = int8_mult(alpha, g(fg)) + int8_mult(alpha_com, g(bg))
      new_b = int8_mult(alpha, b(fg)) + int8_mult(alpha_com, b(bg))
      new_a = int8_mult(alpha, a(fg)) + int8_mult(alpha_com, a(bg))
      
      return rgba(new_r, new_g, new_b, new_a)
    end

    # Calculates the grayscale teint of an RGB color.
    #
    # @param [Integer] color The color to convert.    
    # @return [Integer] The grayscale teint of the input color, 0-255.
    def grayscale_teint(color)
      (r(color) * 0.3 + g(color) * 0.59 + b(color) * 0.11).round
    end
    
    # Converts a color to a fiting grayscale value. It will conserve the alpha
    # channel.
    #
    # This method will return a full color value, with the R, G, and B value set
    # to the grayscale teint calcuated from the input color's R, G and B values.
    #
    # @param [Integer] color The color to convert.
    # @return [Integer] The input color, converted to the best fitting grayscale.
    # @see #grayscale_teint
    def to_grayscale(color)
      grayscale_alpha(grayscale_teint(color), a(color))
    end    

    # Lowers the intensity of a color, by lowering its alpha by a given factor.
    # @param [Integer] color The color to adjust.
    # @param [Integer] factor Fade factor as an integer between 0 and 255.
    # @return [Integer] The faded color.
    def fade(color, factor)
      new_alpha = int8_mult(a(color), factor)
      (color & 0xffffff00) | new_alpha
    end
    
    # Decomposes a color, given a color, a mask color and a background color.
    # The returned color will be a variant of the mask color, with the alpha
    # channel set to the best fitting value. This basically is the reverse 
    # operation if alpha composition.
    #
    # If the color cannot be decomposed, this method will return the fully
    # transparent variant of the mask color.
    #
    # @param [Integer] color The color that was the result of compositing.
    # @param [Integer] mask The opaque variant of the color that was being composed
    # @param [Integer] bg The background color on which the color was composed.
    # @param [Integer] tolerance The decomposition tolerance level, a value between 0 and 255.
    # @return [Integer] The decomposed color,a variant of the masked color with the 
    #    alpha channel set to an appropriate value.
    def decompose_color(color, mask, bg, tolerance = 1)
      if alpha_decomposable?(color, mask, bg, tolerance)
        mask & 0xffffff00 | decompose_alpha(color, mask, bg)
      else
        mask & 0xffffff00
      end
    end
    
    # Checks whether an alpha channel value can successfully be composed
    # given the resulting color, the mask color and a background color,
    # all of which should be opaque. 
    #
    # @param [Integer] color The color that was the result of compositing.
    # @param [Integer] mask The opaque variant of the color that was being composed
    # @param [Integer] bg The background color on which the color was composed.
    # @param [Integer] tolerance The decomposition tolerance level, a value between 0 and 255.
    # @return [Boolean] True if the alpha component can be decomposed successfully.
    # @see #decompose_alpha
    def alpha_decomposable?(color, mask, bg, tolerance = 1)
      components = decompose_alpha_components(color, mask, bg)
      sum = components.inject(0) { |a,b| a + b } 
      max = components.max * 3
      return components.max <= 255 && components.min >= 0 && (sum + tolerance * 3) >= max
    end
    
    # Decomposes the alpha channel value given the resulting color, the mask color 
    # and a background color, all of which should be opaque.
    #
    # Make sure to call {#alpha_decomposable?} first to see if the alpha channel
    # value can successfully decomposed with a given tolerance, otherwise the return 
    # value of this method is undefined.
    #
    # @param [Integer] color The color that was the result of compositing.
    # @param [Integer] mask The opaque variant of the color that was being composed
    # @param [Integer] bg The background color on which the color was composed.
    # @return [Integer] The best fitting alpha channel, a value between 0 and 255.
    # @see #alpha_decomposable?
    def decompose_alpha(color, mask, bg)
      components = decompose_alpha_components(color, mask, bg)
      (components.inject(0) { |a,b| a + b } / 3.0).round
    end
    
    # Decomposes an alpha channel for either the r, g or b color channel.
    # @param [:r, :g, :b] channel The channel to decompose the alpha channel from.
    # @param [Integer] color The color that was the result of compositing.
    # @param [Integer] mask The opaque variant of the color that was being composed
    # @param [Integer] bg The background color on which the color was composed.
    # @return [Integer] The decomposed alpha value for the channel.
    def decompose_alpha_component(channel, color, mask, bg)
      cc, mc, bc = send(channel, color), send(channel, mask), send(channel, bg)
      
      return 0x00 if bc == cc
      return 0xff if bc == mc
      return 0xff if cc == mc
      
      (((bc - cc).to_f / (bc - mc).to_f) * MAX).round
    end
    
    # Decomposes the alpha channels for the r, g and b color channel.
    # @param [Integer] color The color that was the result of compositing.
    # @param [Integer] mask The opaque variant of the color that was being composed
    # @param [Integer] bg The background color on which the color was composed.    
    # @return [Array<Integer>] The decomposed alpha values for the r, g and b channels.
    def decompose_alpha_components(color, mask, bg)
      [
        decompose_alpha_component(:r, color, mask, bg),
        decompose_alpha_component(:g, color, mask, bg),
        decompose_alpha_component(:b, color, mask, bg)
      ]
    end

    ####################################################################
    # CONVERSIONS
    ####################################################################

    # Returns a string representing this color using hex notation (i.e. #rrggbbaa).
    #
    # @param [Integer] value The color to convert.
    # @return [String] The color in hex notation, starting with a pound sign.
    def to_hex(color, include_alpha = true)
      include_alpha ? ('#%08x' % color) : ('#%06x' % [color >> 8])
    end

    # Returns an array with the separate RGBA values for this color.
    #
    # @param [Integer] color The color to convert.
    # @return [Array<Integer>] An array with 4 Integer elements.
    def to_truecolor_alpha_bytes(color)
      [r(color), g(color), b(color), a(color)]
    end

    # Returns an array with the separate RGB values for this color.
    # The alpha channel will be discarded.
    #
    # @param [Integer] color The color to convert.
    # @return [Array<Integer>] An array with 3 Integer elements.
    def to_truecolor_bytes(color)
      [r(color), g(color), b(color)]
    end

    # Returns an array with the grayscale teint value for this color.
    #
    # This method expects the r,g and b value to be equal, and the alpha 
    # channel will be discarded.
    #
    # @param [Integer] color The grayscale color to convert.
    # @return [Array<Integer>] An array with 1 Integer element.
    def to_grayscale_bytes(color)
      [b(color)] # assumption r == g == b
    end

    # Returns an array with the grayscale teint and alpha channel values
    # for this color.
    #
    # This method expects the color to be grayscale, i.e. r,g and b value 
    # to be equal and uses only the B channel. If you need to convert a 
    # color to grayscale first, see {#to_grayscale}.
    #
    # @param [Integer] color The grayscale color to convert.
    # @return [Array<Integer>] An array with 2 Integer elements.
    # @see #to_grascale
    def to_grayscale_alpha_bytes(color)
      [b(color), a(color)] # assumption r == g == b
    end

    ####################################################################
    # COLOR CONSTANTS
    ####################################################################

    # @return [Hash<Symbol, Integer>] All the predefined color names in HTML.
    PREDEFINED_COLORS = {
      :aliceblue => 0xf0f8ff00,
      :antiquewhite => 0xfaebd700,
      :aqua => 0x00ffff00,
      :aquamarine => 0x7fffd400,
      :azure => 0xf0ffff00,
      :beige => 0xf5f5dc00,
      :bisque => 0xffe4c400,
      :black => 0x00000000,
      :blanchedalmond => 0xffebcd00,
      :blue => 0x0000ff00,
      :blueviolet => 0x8a2be200,
      :brown => 0xa52a2a00,
      :burlywood => 0xdeb88700,
      :cadetblue => 0x5f9ea000,
      :chartreuse => 0x7fff0000,
      :chocolate => 0xd2691e00,
      :coral => 0xff7f5000,
      :cornflowerblue => 0x6495ed00,
      :cornsilk => 0xfff8dc00,
      :crimson => 0xdc143c00,
      :cyan => 0x00ffff00,
      :darkblue => 0x00008b00,
      :darkcyan => 0x008b8b00,
      :darkgoldenrod => 0xb8860b00,
      :darkgray => 0xa9a9a900,
      :darkgrey => 0xa9a9a900,
      :darkgreen => 0x00640000,
      :darkkhaki => 0xbdb76b00,
      :darkmagenta => 0x8b008b00,
      :darkolivegreen => 0x556b2f00,
      :darkorange => 0xff8c0000,
      :darkorchid => 0x9932cc00,
      :darkred => 0x8b000000,
      :darksalmon => 0xe9967a00,
      :darkseagreen => 0x8fbc8f00,
      :darkslateblue => 0x483d8b00,
      :darkslategray => 0x2f4f4f00,
      :darkslategrey => 0x2f4f4f00,
      :darkturquoise => 0x00ced100,
      :darkviolet => 0x9400d300,
      :deeppink => 0xff149300,
      :deepskyblue => 0x00bfff00,
      :dimgray => 0x69696900,
      :dimgrey => 0x69696900,
      :dodgerblue => 0x1e90ff00,
      :firebrick => 0xb2222200,
      :floralwhite => 0xfffaf000,
      :forestgreen => 0x228b2200,
      :fuchsia => 0xff00ff00,
      :gainsboro => 0xdcdcdc00,
      :ghostwhite => 0xf8f8ff00,
      :gold => 0xffd70000,
      :goldenrod => 0xdaa52000,
      :gray => 0x80808000,
      :grey => 0x80808000,
      :green => 0x00800000,
      :greenyellow => 0xadff2f00,
      :honeydew => 0xf0fff000,
      :hotpink => 0xff69b400,
      :indianred => 0xcd5c5c00,
      :indigo => 0x4b008200,
      :ivory => 0xfffff000,
      :khaki => 0xf0e68c00,
      :lavender => 0xe6e6fa00,
      :lavenderblush => 0xfff0f500,
      :lawngreen => 0x7cfc0000,
      :lemonchiffon => 0xfffacd00,
      :lightblue => 0xadd8e600,
      :lightcoral => 0xf0808000,
      :lightcyan => 0xe0ffff00,
      :lightgoldenrodyellow => 0xfafad200,
      :lightgray => 0xd3d3d300,
      :lightgrey => 0xd3d3d300,
      :lightgreen => 0x90ee9000,
      :lightpink => 0xffb6c100,
      :lightsalmon => 0xffa07a00,
      :lightseagreen => 0x20b2aa00,
      :lightskyblue => 0x87cefa00,
      :lightslategray => 0x77889900,
      :lightslategrey => 0x77889900,
      :lightsteelblue => 0xb0c4de00,
      :lightyellow => 0xffffe000,
      :lime => 0x00ff0000,
      :limegreen => 0x32cd3200,
      :linen => 0xfaf0e600,
      :magenta => 0xff00ff00,
      :maroon => 0x80000000,
      :mediumaquamarine => 0x66cdaa00,
      :mediumblue => 0x0000cd00,
      :mediumorchid => 0xba55d300,
      :mediumpurple => 0x9370d800,
      :mediumseagreen => 0x3cb37100,
      :mediumslateblue => 0x7b68ee00,
      :mediumspringgreen => 0x00fa9a00,
      :mediumturquoise => 0x48d1cc00,
      :mediumvioletred => 0xc7158500,
      :midnightblue => 0x19197000,
      :mintcream => 0xf5fffa00,
      :mistyrose => 0xffe4e100,
      :moccasin => 0xffe4b500,
      :navajowhite => 0xffdead00,
      :navy => 0x00008000,
      :oldlace => 0xfdf5e600,
      :olive => 0x80800000,
      :olivedrab => 0x6b8e2300,
      :orange => 0xffa50000,
      :orangered => 0xff450000,
      :orchid => 0xda70d600,
      :palegoldenrod => 0xeee8aa00,
      :palegreen => 0x98fb9800,
      :paleturquoise => 0xafeeee00,
      :palevioletred => 0xd8709300,
      :papayawhip => 0xffefd500,
      :peachpuff => 0xffdab900,
      :peru => 0xcd853f00,
      :pink => 0xffc0cb00,
      :plum => 0xdda0dd00,
      :powderblue => 0xb0e0e600,
      :purple => 0x80008000,
      :red => 0xff000000,
      :rosybrown => 0xbc8f8f00,
      :royalblue => 0x4169e100,
      :saddlebrown => 0x8b451300,
      :salmon => 0xfa807200,
      :sandybrown => 0xf4a46000,
      :seagreen => 0x2e8b5700,
      :seashell => 0xfff5ee00,
      :sienna => 0xa0522d00,
      :silver => 0xc0c0c000,
      :skyblue => 0x87ceeb00,
      :slateblue => 0x6a5acd00,
      :slategray => 0x70809000,
      :slategrey => 0x70809000,
      :snow => 0xfffafa00,
      :springgreen => 0x00ff7f00,
      :steelblue => 0x4682b400,
      :tan => 0xd2b48c00,
      :teal => 0x00808000,
      :thistle => 0xd8bfd800,
      :tomato => 0xff634700,
      :turquoise => 0x40e0d000,
      :violet => 0xee82ee00,
      :wheat => 0xf5deb300,
      :white => 0xffffff00,
      :whitesmoke => 0xf5f5f500,
      :yellow => 0xffff0000,
      :yellowgreen => 0x9acd3200
    }
    
    # Gets a color value based on a HTML color name.
    # 
    # The color name is flexible. E.g. <tt>'yellowgreen'</tt>, <tt>'Yellow green'</tt>, 
    # <tt>'YellowGreen'</tt>, <tt>'YELLOW_GREEN'</tt> and <tt>:yellow_green</tt> will
    # all return the same color value.
    #
    # You can include a opacity level in the color name (e.g. <tt>'red @ 0.5'</tt>) or give
    # an explicit opacity value as second argument. If no opacity value is given, the color
    # will be fully opaque.
    #
    # @param [Symbol, String] color_name The color name. It may include an opacity specifier
    #   like <tt>@ 0.8</tt> to set the color's opacity.
    # @param [Integer] opacity The opacity value for the color between 0 and 255. Overrides 
    #   any opacity value given in the color name.
    # @return [Integer] The color value.
    # @raise [ChunkyPNG::Exception] If the color name was not recognized.
    def html_color(color_name, opacity = nil)
      if color_name.to_s =~ HTML_COLOR_REGEXP
        opacity ||= $2 ? ($2.to_f * 255.0).round : 0xff
        base_color_name = $1.gsub(/[^a-z]+/i, '').downcase.to_sym
        return PREDEFINED_COLORS[base_color_name] | opacity if PREDEFINED_COLORS.has_key?(base_color_name)
      end
      raise ArgumentError, "Unknown color name #{color_name}!"
    end

    # @return [Integer] Black pixel/color
    BLACK = rgb(  0,   0,   0)

    # @return [Integer] White pixel/color
    WHITE = rgb(255, 255, 255)

    # @return [Integer] Fully transparent pixel/color
    TRANSPARENT = rgba(0, 0, 0, 0)

    ####################################################################
    # STATIC UTILITY METHODS
    ####################################################################

    # Returns the number of sample values per pixel.
    # @param [Integer] color_mode The color mode being used.
    # @return [Integer] The number of sample values per pixel.
    def samples_per_pixel(color_mode)
      case color_mode
        when ChunkyPNG::COLOR_INDEXED;         1
        when ChunkyPNG::COLOR_TRUECOLOR;       3
        when ChunkyPNG::COLOR_TRUECOLOR_ALPHA; 4
        when ChunkyPNG::COLOR_GRAYSCALE;       1
        when ChunkyPNG::COLOR_GRAYSCALE_ALPHA; 2
        else raise ChunkyPNG::NotSupported, "Don't know the numer of samples for this colormode: #{color_mode}!"
      end
    end

    # Returns the size in bytes of a pixel when it is stored using a given color mode.
    # @param [Integer] color_mode The color mode in which the pixels are stored.
    # @return [Integer] The number of bytes used per pixel in a datastream.
    def pixel_bytesize(color_mode, depth = 8)
      return 1 if depth < 8
      (pixel_bitsize(color_mode, depth) + 7) >> 3
    end
    
    # Returns the size in bits of a pixel when it is stored using a given color mode.
    # @param [Integer] color_mode The color mode in which the pixels are stored.
    # @param [Integer] depth The color depth of the pixels.
    # @return [Integer] The number of bytes used per pixel in a datastream.
    def pixel_bitsize(color_mode, depth = 8)
      samples_per_pixel(color_mode) * depth
    end
    
    # Returns the number of bytes used per scanline.
    # @param [Integer] color_mode The color mode in which the pixels are stored.
    # @param [Integer] depth The color depth of the pixels.
    # @param [Integer] width The number of pixels per scanline.
    # @return [Integer] The number of bytes used per scanline in a datastream.
    def scanline_bytesize(color_mode, depth, width)
      ((pixel_bitsize(color_mode, depth) * width) + 7) >> 3
    end
    
    # Returns the number of bytes used for an image pass
    # @param [Integer] color_mode The color mode in which the pixels are stored.
    # @param [Integer] depth The color depth of the pixels.
    # @param [Integer] width The width of the image pass.
    # @param [Integer] width The height of the image pass.
    # @return [Integer] The number of bytes used per scanline in a datastream.
    def pass_bytesize(color_mode, depth, width, height)
      return 0 if width == 0 || height == 0
      (scanline_bytesize(color_mode, depth, width) + 1) * height
    end
  end
end
