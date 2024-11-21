# -*- coding: binary -*-

#
# This mixin is a simplistic implementation of X11 extensions protocol
#
# Wireshark dissector: https://wiki.wireshark.org/X11
#

module Rex::Proto::X11::Window
  # 3 =  https://xcb.freedesktop.org/manual/structxcb__get__window__attributes__request__t.html
  # 14 = https://xcb.freedesktop.org/manual/structxcb__get__geometry__request__t.html
  class X11GetRequest < BinData::Record
    endian :little
    uint8 :opcode # 3 = GetWindowAttributes, 14 = GetGeometry
    uint8 :pad # XXX seems to be increasing counter...
    uint16 :request_length, value: -> { num_bytes / 4 }
    uint32 :window # X11ConnectionResponse.screen_root
  end

  # https://xcb.freedesktop.org/manual/structxcb__get__window__attributes__reply__t.html
  class X11GetWindowAttributeResponse < BinData::Record
    endian :little
    uint8 :depth
    uint16 :visual_id
    uint8 :class_name
    uint8 :bit_gravity
    uint8 :win_gravity
    uint32 :backing_planes
    uint32 :backing_pixel
    uint8 :save_under
    uint8 :map_is_installed
    uint8 :map_state
    uint8 :override_redirect
    uint32 :colormap
    uint32 :all_event_masks
    uint32 :your_event_mask
    uint16 :do_not_propagate_mask
  end

  # https://xcb.freedesktop.org/manual/structxcb__get__geometry__reply__t.html
  class X11GetGeometryResponse < BinData::Record
    endian :little
    uint8 :depth
    uint32 :root
    uint16 :x
    uint16 :y
    uint16 :width
    uint16 :height
    uint16 :border_width
  end

  # https://xcb.freedesktop.org/manual/structxcb__get__geometry__reply__t.html
  class X11GetWindowAttributesGeometryResponse < BinData::Record
    endian :little
    uint8 :reply
    uint8 :depth
    uint16 :sequence_number
    uint32 :response_length
    uint32 :root
    uint16 :x
    uint16 :y
    uint16 :width
    uint16 :height
    uint16 :border_width
  end

  # https://xcb.freedesktop.org/manual/structxcb__translate__coordinates__request__t.html
  class X11TranslateCoordinatesRequest < BinData::Record
    endian :little
    uint8 :opcode, value: 40 # TranslateCoordinates
    uint8 :pad # XXX seems to be increasing counter...
    uint16 :request_length, value: -> { num_bytes / 4 }
    uint32 :src_window # X11ConnectionResponse.screen_root
    uint32 :dst_window # X11ConnectionResponse.screen_root
    uint16 :src_x
    uint16 :src_y
  end

  # https://xcb.freedesktop.org/manual/structxcb__query__tree__request__t.html
  class X11QueryTreeRequest < BinData::Record
    endian :little
    uint8 :opcode, value: 15 # QueryTree
    uint8 :pad, initial_value: 1 # XXX counter?
    uint16 :request_length, value: -> { num_bytes / 4 }
    uint32 :drawable # X11ConnectionResponse.screen_root
  end

  # https://xcb.freedesktop.org/manual/structxcb__query__tree__reply__t.html
  class X11QueryTreeResponse < BinData::Record
    endian :little
    uint8 :reply
    uint8 :pad0
    uint16 :sequence_number
    uint32 :response_length
    uint32 :root_window
    uint32 :parent_window
    uint32 :children_len
    uint32 :unsure
    uint32 :unsure1
    uint32 :unsure2
    array :children,
          type: :uint32,
          initial_length: :children_len
  end

  # https://xcb.freedesktop.org/manual/structxcb__get__image__request__t.html
  class X11GetImageRequest < BinData::Record
    endian :little
    uint8 :opcode, value: 73 # GetImage
    uint8 :image_pixmap_format, initial_value: 2 # zpixmap, better than 0 xypixmap
    uint16 :request_length, value: -> { num_bytes / 4 }
    uint32 :drawable # window/X11ConnectionResponse.screen_root
    uint16 :x
    uint16 :y
    uint16 :width
    uint16 :height
    uint32 :plane_mask, initial_value: 4294967295 # AllPlanes \xff\xff\xff\xff
  end

  # https://xcb.freedesktop.org/manual/structxcb__get__image__reply__t.html
  class X11GetImageResponse < BinData::Record
    endian :little
    uint8 :response_type
    uint8 :depth
    uint16 :sequence_number
    uint32 :response_length
    uint32 :visual_id
    array :image_data,
          type: :uint8,
          initial_length: :response_length
  end

  # https://xcb.freedesktop.org/manual/structxcb__query__colors__request__t.html
  class X11GetColorsRequest < BinData::Record
    endian :little
    uint8 :opcode, value: 91 # QueryColors
    uint8 :pad0
    uint16 :request_length, value: -> { num_bytes / 4 }
    uint32 :color_map
    array :pixels,
          type: :uint32, # this is likely 00 RR GG BB (uint8 for each)
          read_until: :eof
  end

  # https://xcb.freedesktop.org/manual/structxcb__rgb__t.html -ish, as the first pixel seems unused
  class X11Color < BinData::Record
    endian :little
    uint16 :pad0
    uint16 :red
    uint16 :green
    uint16 :blue
  end

  # https://xcb.freedesktop.org/manual/structxcb__query__colors__reply__t.html
  class X11GetColorsResponse < BinData::Record
    endian :little
    uint8 :response_type
    uint8 :pad0
    uint16 :sequence
    uint32 	:response_length
    uint16 	:colors_len
    array :colors,
          initial_length: :colors_len,
          type: :X11Color
  end

  # https://xcb.freedesktop.org/manual/structxcb__get__window__attributes__reply__t.html
  class X11GetWindowResponse < BinData::Record
    endian :little
    uint8 :response_type
    uint8 :backing_store
    uint16 :sequence_number
    uint32 :response_length
    uint32 :visual_id
    uint16 :window_class
    bit8 :bit_gravity
    bit8 :win_gravity
    bit32 :backing_planes
    bit32 :backing_pixel
    bit8 :save_under
    bit8 :map_is_installed
    bit8 :map_state
    bit8 :override_redirect
    uint32 :colormap
    uint32 :all_event_masks
    uint32 :your_event_mask
    uint16 :do_not_propagate_mask
    array :pad,
          type: :uint8,
          initial_length: 2
  end
end

# for future use
# def create_overlay_map(screen_width, screen_height, windows)
#   # Initialize a 2D array to represent the screen
#   screen = Array.new(screen_height) { Array.new(screen_width, nil) }
#   windows.each_with_index do |window, i|
#     puts window.inspect
#     x, y, width, height = window
#     # Mark the visible region occupied by the window
#     (y...y + height).each do |row|
#       (x...x + width).each do |col|
#         screen[row][col] = i
#       end
#     end
#   end
#   screen.each do |row|
#     puts row.join('')
#   end
# end

class X11Image
  def initialize(width, height, image_data, color_data)
    @width = width # integer, 1024 in 1024×768
    @height = height # integer, 768 in 1024×768
    @image_data = image_data # from X11GetImageResponse
    @color_data = color_data # from X11GetColorsResponse
  end

  def self.from_replies(width, height, image_reply, color_reply)
    new(width, height, image_reply.image_data, color_reply.colors)
  end

  # for future use
  # def create_image
  #   # Extract relevant data from @image_data and @color_data
  #   width = @width
  #   height = @height
  #   pixel_data = @image_data
  #   colors = @color_data

  #   # Create an image object
  #   image = ChunkyPNG::Image.new(width, height, ChunkyPNG::Color::TRANSPARENT)

  #   # Populate image with pixel data and colors
  #   pixel_data.each_with_index do |pixel, i|
  #     color = colors[pixel]
  #     # Set pixel color in the image
  #     image[i % width, i / width] = ChunkyPNG::Color.rgb(color.red, color.green, color.blue)
  #   end
  #   # (0...height).each do |y|
  #   #   (0...width).each do |x|
  #   #     # Extract color information from the pixel data and set the corresponding pixel in the PNG image
  #   #     color = colors[y+x]
  #   #     # pixel_color = extract_color_from_z_data(z_data)
  #   #     image[x, y] = ChunkyPNG::Color.rgb(color.red, color.green, color.blue)
  #   #   end
  #   # end

  #   image
  # end
end
