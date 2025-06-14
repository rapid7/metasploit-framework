# -*- coding: binary -*-

#
# This mixin is a simplistic implementation of X11 extensions protocol
#
# Wireshark dissector: https://wiki.wireshark.org/X11
#

module Rex::Proto::X11::Extensions
  # https://xcb.freedesktop.org/manual/structxcb__query__extension__reply__t.html
  class X11QueryExtensionResponse < BinData::Record
    endian :little
    uint8 :reply
    uint8 :pad
    uint16 :sequence_number # QueryExtension
    uint32 :response_length
    uint8 :present # 8bit boolean, \x01 == true \x00 == false
    uint8 :major_opcode # this is the ID of the extension
    uint8 :first_event
    uint8 :first_error
  end

  # https://xcb.freedesktop.org/manual/structxcb__query__extension__request__t.html
  class X11QueryExtensionRequest < BinData::Record
    endian :little
    uint8 :opcode, value: 98 # QueryExtension
    uint8 :pad0, value: 0
    uint16 :request_length, value: -> { num_bytes / 4 }
    uint16 :extension_length, value: -> { extension.to_s.gsub(/\x00+\z/, '').length } # cut off the \x00 padding
    uint16 :pad1, initial_value: 0 # seems to possibly be a counter for how many times this has been called
    string :extension, length: 12, trim_padding: true
  end

  class X11ExtensionToggleRequest < BinData::Record
    endian :little
    uint8 :opcode # X11QueryExtensionResponse.major-opcode
    uint8 :toggle, initial_value: 0 # 0 enable
    uint16 :request_length, value: -> { num_bytes / 4 }
    uint16 :wanted_major, onlyif: :versions? # extension major version
    uint16 :wanted_minor, onlyif: :versions? # extension minor version

    def versions?
      wanted_major.nonzero? || wanted_minor.nonzero?
    end
  end
end
