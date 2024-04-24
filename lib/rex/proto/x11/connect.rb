# -*- coding: binary -*-

#
# This mixin is a simplistic implementation of X11 initial connection protocol
#
# Wireshark dissector: https://wiki.wireshark.org/X11
#

module Msf::Exploit::Remote::X11::Connect
  # https://xcb.freedesktop.org/manual/structxcb__visualtype__t.html
  class X11VisualType < BinData::Record
    endian :little
    uint32 :visualid
    uint8 :visual_type_classclass
    uint8 :bits_per_rgb_value
    uint16 :colormap_entries
    uint32 :red_mask
    uint32 :green_mask
    uint32 :blue_mask
    uint32 :pad
  end

  # https://xcb.freedesktop.org/manual/structxcb__depth__t.html
  class X11DepthDetail < BinData::Record
    endian :little
    uint8 :depth
    uint8 :pad0
    uint16 :visualtypes_numbers
    uint32 :pad1
    array :depth_detail,
          type: :X11VisualType,
          initial_length: :visualtypes_numbers
  end

  # https://xcb.freedesktop.org/manual/structxcb__format__t.html
  class X11PixMapFormat < BinData::Record
    endian :little
    uint8 :depth
    uint8 :bits_per_pixel
    uint8 :scanline_pad
    uint8 :pad0
    uint32 :pad1
  end

  # https://xcb.freedesktop.org/manual/structxcb__setup__t.html
  class X11ConnectionResponse < BinData::Record
    endian :little
    uint8 :success # 8bit boolean, \x01 == true \x00 == false
    uint8 :pad0
    uint16 :protocol_version_major
    uint16 :protocol_version_minor
    uint16 :response_length
    uint32 :release_number
    uint32 :resource_id_base
    uint32 :resource_id_mask
    uint32 :motion_buffer_size
    uint16 :vendor_length
    uint16 :maximum_request_length
    uint8 :number_of_screens_in_root
    uint8 :number_of_formats_in_pixmap_formats
    uint8 :image_byte_order
    uint8 :bitmap_format_bit_order
    uint8 :bitmap_format_scanline_unit
    uint8 :bitmap_format_scanline_pad
    uint8 :min_keycode
    uint8 :max_keycode
    uint32 :pad1
    string :vendor, read_length: :vendor_length
    array :pixmap_formats,
          type: :X11PixMapFormat,
          initial_length: :number_of_formats_in_pixmap_formats

    # screen subsection
    uint32 :screen_root
    uint32 :screen_default_colormap
    uint32 :screen_white_pixel
    uint32 :screen_black_pixel
    uint32 :screen_current_input_masks
    uint16 :screen_width_in_pixels
    uint16 :screen_height_in_pixels
    uint16 :screen_width_in_millimeters
    uint16 :screen_height_in_millimeters
    uint16 :screen_min_installed_maps
    uint16 :screen_max_installed_maps
    uint32 :screen_root_visual
    uint8 :screen_backing_stores
    uint8 :screen_save_unders # 8bit boolean, \x01 == true \x00 == false
    uint8 :screen_root_depth
    uint8 :screen_allowed_depths_len
    array :depth_detail,
          type: :X11DepthDetail,
          initial_length: :screen_allowed_depths_len
  end

  # https://xcb.freedesktop.org/manual/structxcb__setup__request__t.html
  class X11ConnectionRequest < BinData::Record
    # only 1/2 implemented since we dont have any authorization items added
    endian :little
    uint8 :byte_order, value: 108 # Little-endian
    uint8 :pad0, value: 0
    uint16 :protocol_version_major, value: 11
    uint16 :protocol_version_minor, value: 0
    uint16 :authorization_protocol_name_length, value: 0
    uint16 :authorization_protocol_data_length, value: 0
    uint16 :pad1, value: 0
  end

  def print_connection_info(connection, ip, port)
    print_good("#{ip} - Successly established X11 connection")
        vprint_status("  Vendor: #{connection.vendor}")
        vprint_status("  Version: #{connection.protocol_version_major}.#{connection.protocol_version_minor}")
        vprint_status("  Screen Resolution: #{connection.screen_width_in_pixels}x#{connection.screen_height_in_pixels}")
        vprint_status("  Resource ID: #{connection.resource_id_base.inspect}")
        vprint_status("  Screen root: #{connection.screen_root.inspect}")
        report_note(
          host: ip,
          proto: 'tcp',
          sname: 'x11',
          port: port,
          type: 'x11.server_vendor',
          data: "Open X Server (#{connection.vendor})"
        )
  end
end
