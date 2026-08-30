# -*- coding: binary -*-

#
# This mixin is a simplistic implementation of X11
#
# Wireshark dissector: https://wiki.wireshark.org/X11
#

module Rex::Proto::X11
  include Rex::Proto::X11::Connect
  include Rex::Proto::X11::Extension
  include Rex::Proto::X11::Xkeyboard
  include Rex::Proto::X11::Keysymdef
  include Rex::Proto::X11::Window

  # https://xcb.freedesktop.org/manual/structxcb__generic__error__t.html
  class X11Error < BinData::Record
    endian :little
    uint8 :response_type # 0 = Error, 1 = Reply
    uint8 :error_code # 8 = BadMatch
    uint16 :sequence_number
    uint32 :bad_value
    uint16 :minor_opcode
    uint16 :major_opcode
    uint8 :pad0
  end

  # https://xcb.freedesktop.org/manual/structxcb__get__property__reply__t.html
  class X11GetPropertyResponse < BinData::Record
    endian :little
    uint8 :reply
    uint8 :format
    uint16 :sequence_number # GetProperty
    uint32 :response_length
    uint32 :get_property_type # 8bit boolean, \x01 == true \x00 == false
    uint32 :bytes_after
    uint32 :value_length
    uint8_array :pad0, initial_length: 12
    rest :value_data
  end

  # https://xcb.freedesktop.org/manual/structxcb__intern__atom__reply__t.html
  class X11InternAtomResponse < BinData::Record
    endian :little
    uint8 :reply
    uint8 :pad0
    uint16 :sequence_number
    uint32 :response_length
    uint32 :atom
    rest :pad1
  end

  # https://xcb.freedesktop.org/manual/structxcb__get__property__request__t.html
  class X11GetPropertyRequestBody < BinData::Record
    endian :little
    uint8 :delete_field, initial_value: 0 # \x00 false, assuming \x01 true?
    uint16 :request_length, value: -> { (num_bytes / 4) + 1 } # +1 for header opcode
    uint32 :window # X11ConnectionResponse.screen_root
    uint32 :property, initial_value: 23 # "\x17\x00\x00\x00" RESOURCE_MANAGER
    uint32 :get_property_type, initial_value: 31 # "\x1f\x00\x00\x00" # get-property-type (31 = string)
    uint32 :long_offset, value: 0
    uint32 :content_length, value: 100_000_000 # "\x00\xe1\xf5\x05"
  end

  # https://xcb.freedesktop.org/manual/structxcb__create__gc__request__t.html
  class X11CreateGraphicalContextRequestBody < BinData::Record
    endian :little
    uint8 :pad0
    uint16 :request_length, value: -> { (num_bytes / 4) + 1 } # +1 for header opcode
    uint32 :cid # X11ConnectionResponse.resource_id
    uint32 :drawable # X11ConnectionResponse.screen_root
    # gc-value-mask mappings from wireshark, uint32 total size
    # .... .... .... .... .... .... .... ...0 = function: False
    # .... .... .... .... .... .... .... ..0. = plane-mask: False
    # .... .... .... .... .... .... .... .0.. = foreground: False
    # .... .... .... .... .... .... .... 1... = background: True
    # .... .... .... .... .... .... ...0 .... = line-width: False
    # .... .... .... .... .... .... ..0. .... = line-style: False
    # .... .... .... .... .... .... .0.. .... = cap-style: False
    # .... .... .... .... .... .... 0... .... = join-style: False
    # .... .... .... .... .... ...0 .... .... = fill-style: False
    # .... .... .... .... .... ..0. .... .... = fill-rule: False
    # .... .... .... .... .... .0.. .... .... = tile: False
    # .... .... .... .... .... 0... .... .... = stipple: False
    # .... .... .... .... ...0 .... .... .... = tile-stipple-x-origin: False
    # .... .... .... .... ..0. .... .... .... = tile-stipple-y-origin: False
    # .... .... .... .... .0.. .... .... .... = font: False
    # .... .... .... .... 0... .... .... .... = subwindow-mode: False
    # .... .... .... ...0 .... .... .... .... = graphics-exposures: False
    # .... .... .... ..0. .... .... .... .... = clip-x-origin: False
    # .... .... .... .0.. .... .... .... .... = clip-y-origin: False
    # .... .... .... 0... .... .... .... .... = clip-mask: False
    # .... .... ...0 .... .... .... .... .... = dash-offset: False
    # .... .... ..0. .... .... .... .... .... = gc-dashes: False
    # .... .... .0.. .... .... .... .... .... = arc-mode: False
    bit1 :gc_value_mask_join_style, initial_value: 0
    bit1 :gc_value_mask_cap_style, initial_value: 0
    bit1 :gc_value_mask_line_style, initial_value: 0
    bit1 :gc_value_mask_line_width, initial_value: 0
    bit1 :gc_value_mask_background, initial_value: 0
    bit1 :gc_value_mask_foreground, initial_value: 0
    bit1 :gc_value_mask_plane_mask, initial_value: 0
    bit1 :gc_value_mask_function, initial_value: 0

    bit1 :gc_value_mask_subwindow_mode, initial_value: 0
    bit1 :gc_value_mask_font, initial_value: 0
    bit1 :gc_value_mask_tile_stipple_y_origin, initial_value: 0
    bit1 :gc_value_mask_tile_stipple_x_origin, initial_value: 0
    bit1 :gc_value_mask_stipple, initial_value: 0
    bit1 :gc_value_mask_tile, initial_value: 0
    bit1 :gc_value_mask_fill_rule, initial_value: 0
    bit1 :gc_value_mask_fill_style, initial_value: 0

    bit1 :gc_value_mask_arc_mode, initial_value: 0
    bit1 :gc_value_mask_gc_dashes, initial_value: 0
    bit1 :gc_value_mask_dash_offset, initial_value: 0
    bit1 :gc_value_mask_clip_mask, initial_value: 0
    bit1 :gc_value_mask_clip_y_origin, initial_value: 0
    bit1 :gc_value_mask_clip_x_origin, initial_value: 0
    bit1 :gc_value_mask_graphics_exposures, initial_value: 0
    bit1 :gc_value_null_pad

    bit8 :gc_value_null_pad1

    uint32 :background, initial_value: 16777215
  end

  # https://xcb.freedesktop.org/manual/structxcb__free__gc__request__t.html
  class X11FreeGraphicalContextRequestBody < BinData::Record
    endian :little
    uint8 :pad0, value: 1
    uint16 :request_length, value: -> { (num_bytes / 4) + 1 } # +1 for header opcode
    uint32 :gc # X11ConnectionResponse.resource_id_base
  end

  # https://xcb.freedesktop.org/manual/structxcb__get__input__focus__request__t.html
  class X11GetInputFocusRequestBody < BinData::Record
    endian :little
    uint8 :pad0
    uint16 :request_length, value: -> { (num_bytes / 4) + 1 } # +1 for header opcode
  end

  # https://xcb.freedesktop.org/manual/structxcb__intern__atom__request__t.html
  class X11InternAtomRequestBody < BinData::Record
    endian :little
    uint8 :only_if_exists, initial_value: 0 # 0 false, 1 true?
    uint16 :request_length, value: -> { (num_bytes / 4) + 1 } # +1 for header opcode
    uint16 :name_length, value: -> { name.to_s.gsub(/\x00+\z/, '').length } # cut off the \x00 padding
    uint16 :pad0, initial_value: 0
    string :name, trim_padding: true
  end

  # header used for creating requests
  class X11RequestHeader < BinData::Record
    endian :little
    uint8 :opcode
  end

  # x11 request meta class for handling headers and bodies
  class X11Request < BinData::Record
    endian :little
    x11_request_header :header
    choice             :body, selection: -> { header.opcode } do
      x11_intern_atom_request_body 16
      x11_get_property_request_body 20
      x11_get_input_focus_request_body 43
      x11_create_graphical_context_request_body 55
      x11_free_graphical_context_request_body 60
    end
  end
end
