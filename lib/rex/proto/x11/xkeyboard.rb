# -*- coding: binary -*-

#
# This mixin is a simplistic implementation of X11 xkeyboard protocol
#
# Wireshark dissector: https://wiki.wireshark.org/X11
#

module Rex::Proto::X11::Xkeyboard
  # https://xcb.freedesktop.org/manual/structxcb__xkb__key__mod__map__t.html
  class X11KeyModMap < BinData::Record
    endian :little
    uint8 :keycode
    uint8 :mods # bit array, shift, lock, control, 1, 2, 3, 4, 5
  end

  # https://xcb.freedesktop.org/manual/structxcb__xkb__key__sym__map__iterator__t.html
  class X11Sym < BinData::Uint32le
  end

  # https://xcb.freedesktop.org/manual/structxcb__xkb__key__sym__map__t.html
  class X11KeySymEntry < BinData::Record
    endian :little
    uint32 :kt_index
    uint8 :group_info
    uint8 :width
    uint16 :n_syms
    # next we have a list of syms, length is n_syms
    array :key_sym_array,
          type: :X11Sym,
          initial_length: :n_syms
  end

  # https://xcb.freedesktop.org/manual/structxcb__xkb__mod__def__t.html
  class X11ModDef < BinData::Record
    endian :little
    uint8 :mask
    uint8 :real_mods
    uint16 :vmods
  end

  # https://xcb.freedesktop.org/manual/structxcb__xkb__kt__map__entry__t.html
  class X11KeyMapEntry < BinData::Record
    endian :little
    uint8 :active
    uint8 :mods_mask # bit array, shift, lock, control, 1, 2, 3, 4, 5
    uint8 :level
    uint8 :mods_mods # bit array, shift, lock, control, 1, 2, 3, 4, 5
    uint16 :mods_vmods # bit array, 0-15
    uint16 :pad
  end

  # https://xcb.freedesktop.org/manual/structxcb__xkb__key__type__t.html
  class X11KeyType < BinData::Record
    endian :little
    uint8 :mods_mask
    uint8 :mods_mods
    uint16 :mods_vmods
    uint8 :num_levels
    uint8 :n_map_entries
    uint8 :has_preserve # 8bit boolean, \x01 == true \x00 == false
    uint8 :pad
    # next we have a list of KEYMAPENTRY, length is :n_map_entries
    array :key_map_array,
          type: :X11KeyMapEntry,
          initial_length: :n_map_entries
    # not sure how to tell how many of these there are
    array :key_mods_array,
          type: :X11ModDef,
          initial_length: :n_map_entries,
          onlyif: -> { has_preserve == 1 }
  end

  # https://xcb.freedesktop.org/manual/structxcb__xkb__get__map__request__t.html
  class X11GetMapRequest < BinData::Record
    endian :little
    uint8 :xkeyboard_id # opcode
    uint8 :extension_minor, value: 8 # GetMap
    uint16 :request_length, value: -> { num_bytes / 4 }
    uint16 :device_spec, value: 256 # XXX does this come from elsewhere?
    # full mappings from wireshark, uint16 total size
    # .... .... .... ...0 = KeyTypes: False
    # .... .... .... ..0. = KeySyms: False
    # .... .... .... .0.. = ModifierMap: False
    # .... .... .... 0... = ExplicitComponents: False
    # .... .... ...0 .... = KeyActions: False
    # .... .... ..0. .... = KeyBehaviors: False
    # .... .... .0.. .... = VirtualMods: False
    # .... .... 0... .... = VirtualModMap: False
    bit1 :full_virtual_mod_map, initial_value: 0
    bit1 :full_virtual_mods, initial_value: 0
    bit1 :full_key_behaviors, initial_value: 0
    bit1 :full_key_actions, initial_value: 0
    bit1 :full_explicit_components, initial_value: 0
    bit1 :full_modifier_map, initial_value: 0
    bit1 :full_key_syms, initial_value: 0
    bit1 :full_key_types, initial_value: 0
    bit8 :full_null_pad, value: 0

    # partial mappings from wireshark, uint16 total size
    # .... .... .... ...0 = KeyTypes: False
    # .... .... .... ..0. = KeySyms: False
    # .... .... .... .0.. = ModifierMap: False
    # .... .... .... 0... = ExplicitComponents: False
    # .... .... ...0 .... = KeyActions: False
    # .... .... ..0. .... = KeyBehaviors: False
    # .... .... .0.. .... = VirtualMods: False
    # .... .... 0... .... = VirtualModMap: False
    bit1 :partial_virtual_mod_map, initial_value: 0
    bit1 :partial_virtual_mods, initial_value: 0
    bit1 :partial_key_behaviors, initial_value: 0
    bit1 :partial_key_actions, initial_value: 0
    bit1 :partial_explicit_components, initial_value: 0
    bit1 :partial_modifier_map, initial_value: 0
    bit1 :partial_key_syms, initial_value: 0
    bit1 :partial_key_types, initial_value: 0
    bit8 :partial_null_pad, value: 0

    uint8 :first_type
    uint8 :n_types
    uint8 :first_key_sym
    uint8 :n_key_syms
    uint8 :first_key_action
    uint8 :n_key_action
    uint8 :first_key_behavior
    uint8 :n_key_behavior
    bit1 :virtual_mod1, initial_value: 0
    bit1 :virtual_mod2, initial_value: 0
    bit1 :virtual_mod3, initial_value: 0
    bit1 :virtual_mod4, initial_value: 0
    bit1 :virtual_mod5, initial_value: 0
    bit1 :virtual_mod6, initial_value: 0
    bit1 :virtual_mod7, initial_value: 0
    bit1 :virtual_mod8, initial_value: 0
    bit1 :virtual_mod9, initial_value: 0
    bit1 :virtual_mod10, initial_value: 0
    bit1 :virtual_mod11, initial_value: 0
    bit1 :virtual_mod12, initial_value: 0
    bit1 :virtual_mod13, initial_value: 0
    bit1 :virtual_mod14, initial_value: 0
    bit1 :virtual_mod15, initial_value: 0
    bit1 :virtual_mod16, initial_value: 0
    uint8 :first_key_explicit
    uint8 :n_key_explicit
    uint8 :first_mod_map_key
    uint8 :n_mod_map_keys
    uint8 :first_vmod_map_key
    uint8 :n_vmod_map_keys
    uint16 :pad
  end

  # https://xcb.freedesktop.org/manual/structxcb__xkb__get__map__reply__t.html
  class X11GetMapResponse < BinData::Record
    endian :little
    uint8 :reply
    uint8 :device_id
    uint16 :sequence_number # xkb-GetMap
    uint32 :response_length
    uint16 :pad0 # 2x uint8 pads, we just combine
    uint8 :min_key_code
    uint8 :max_key_code
    uint16 :presents # needs to be converted to bits...
    uint8 :first_type
    uint8 :n_types
    uint8 :total_types
    uint8 :first_key_sym
    uint16 :total_sym
    uint8 :n_key_sym
    uint8 :first_key_action
    uint16 :total_key_action
    uint8 :n_key_action
    uint8 :first_key_behavior
    uint8 :n_key_behavior # yes this order is not like the previous
    uint8 :total_key_behavior
    uint8 :first_key_explicit
    uint8 :n_key_explicit
    uint8 :total_key_explicit
    uint8 :first_mod_map_key
    uint8 :n_mod_map_key
    uint8 :total_mod_map_key
    uint8 :first_vmod_map_key
    uint8 :n_vmod_map_key
    uint8 :total_vmod_map_key
    uint8 :pad1
    uint16 :virtual_mods # bit array
    # next we have a list of KEYTYPE, length is :n_types
    array :key_types_array,
          type: :X11KeyType,
          initial_length: :n_types
    # next we have a list of X11KeySymEntry
    array :key_map_array,
          type: :X11KeySymEntry,
          initial_length: :n_key_sym
    # next we have a list of X11KeyModMap
    array :key_mod_map_array,
          type: :X11KeyModMap,
          initial_length: :total_mod_map_key
    rest :pad2
  end

  # https://xcb.freedesktop.org/manual/structxcb__xkb__select__events__request__t.html
  class X11SelectEvents < BinData::Record
    endian :little
    uint8 :xkeyboard_id # opcode
    uint8 :extension_minor, value: 1 # SelectEvent
    uint16 :request_length, value: -> { num_bytes / 4 }
    uint16 :device_spec, value: 3
    # affect_which mappings from wireshark, uint16 total size
    # .... .... .... ...0 = NewKeyboardNotify: False
    # .... .... .... ..0. = MapNotify: False
    # .... .... .... .0.. = StateNotify: False
    # .... .... .... 0... = ControlsNotify: False
    # .... .... ...0 .... = IndicatorStateNotify: False
    # .... .... ..0. .... = IndicatorMapNotify: False
    # .... .... .0.. .... = NamesNotify: False
    # .... .... 0... .... = CompatMapNotify: False
    # .... ...0 .... .... = BellNotify: False
    # .... ..0. .... .... = ActionMessage: False
    # .... .0.. .... .... = AccessXNotify: False
    # .... 0... .... .... = ExtensionDeviceNotify: False
    bit1 :affect_which_compat_map_notify, initial_value: 0
    bit1 :affect_which_names_notify, initial_value: 0
    bit1 :affect_which_indicator_map_notify, initial_value: 0
    bit1 :affect_which_indicator_state_notify, initial_value: 0
    bit1 :affect_which_controls_notify, initial_value: 0
    bit1 :affect_which_state_notify, initial_value: 0
    bit1 :affect_which_map_notify, initial_value: 0
    bit1 :affect_which_new_keyboard_notify, initial_value: 0

    bit4 :affect_which_null_pad, value: 0
    bit1 :affect_which_extension_device_notify, initial_value: 0
    bit1 :affect_which_access_x_notify, initial_value: 0
    bit1 :affect_which_action_message, initial_value: 0
    bit1 :affect_which_bell_notify, initial_value: 0
    # clear mappings from wireshark, uint16 total size
    # .... .... .... ...0 = NewKeyboardNotify: False
    # .... .... .... ..0. = MapNotify: False
    # .... .... .... .0.. = StateNotify: False
    # .... .... .... 0... = ControlsNotify: False
    # .... .... ...0 .... = IndicatorStateNotify: False
    # .... .... ..0. .... = IndicatorMapNotify: False
    # .... .... .0.. .... = NamesNotify: False
    # .... .... 0... .... = CompatMapNotify: False
    # .... ...0 .... .... = BellNotify: False
    # .... ..0. .... .... = ActionMessage: False
    # .... .0.. .... .... = AccessXNotify: False
    # .... 0... .... .... = ExtensionDeviceNotify: False
    bit1 :clear_compat_map_notify, initial_value: 0
    bit1 :clear_names_notify, initial_value: 0
    bit1 :clear_indicator_map_notify, initial_value: 0
    bit1 :clear_indicator_state_notify, initial_value: 0
    bit1 :clear_controls_notify, initial_value: 0
    bit1 :clear_state_notify, initial_value: 0
    bit1 :clear_map_notify, initial_value: 0
    bit1 :clear_new_keyboard_notify, initial_value: 0

    bit4 :clear_null_pad, value: 0
    bit1 :clear_extension_device_notify, initial_value: 0
    bit1 :clear_access_x_notify, initial_value: 0
    bit1 :clear_action_message, initial_value: 0
    bit1 :clear_bell_notify, initial_value: 0
    # select_all mappings from wireshark, uint16 total size
    # .... .... .... ...0 = NewKeyboardNotify: False
    # .... .... .... ..0. = MapNotify: False
    # .... .... .... .0.. = StateNotify: False
    # .... .... .... 0... = ControlsNotify: False
    # .... .... ...0 .... = IndicatorStateNotify: False
    # .... .... ..0. .... = IndicatorMapNotify: False
    # .... .... .0.. .... = NamesNotify: False
    # .... .... 0... .... = CompatMapNotify: False
    # .... ...0 .... .... = BellNotify: False
    # .... ..0. .... .... = ActionMessage: False
    # .... .0.. .... .... = AccessXNotify: False
    # .... 0... .... .... = ExtensionDeviceNotify: False
    bit1 :select_all_compat_map_notify, initial_value: 0
    bit1 :select_all_names_notify, initial_value: 0
    bit1 :select_all_indicator_map_notify, initial_value: 0
    bit1 :select_all_indicator_state_notify, initial_value: 0
    bit1 :select_all_controls_notify, initial_value: 0
    bit1 :select_all_state_notify, initial_value: 0
    bit1 :select_all_map_notify, initial_value: 0
    bit1 :select_all_new_keyboard_notify, initial_value: 0

    bit4 :select_all_null_pad, value: 0
    bit1 :select_all_extension_device_notify, initial_value: 0
    bit1 :select_all_access_x_notify, initial_value: 0
    bit1 :select_all_action_message, initial_value: 0
    bit1 :select_all_bell_notify, initial_value: 0
    # affect_map mappings from wireshark, uint16 total size
    # .... .... .... ...0 = KeyTypes: False
    # .... .... .... ..0. = KeySyms: False
    # .... .... .... .0.. = ModifierMap: False
    # .... .... .... 0... = ExplicitComponents: False
    # .... .... ...0 .... = KeyActions: False
    # .... .... ..0. .... = KeyBehaviors: False
    # .... .... .0.. .... = VirtualMods: False
    # .... .... 0... .... = VirtualModMap: False
    bit1 :affect_map_virtual_mod_map, initial_value: 0
    bit1 :affect_map_virtual_mods, initial_value: 0
    bit1 :affect_map_key_behaviors, initial_value: 0
    bit1 :affect_map_key_actions, initial_value: 0
    bit1 :affect_map_explicit_components, initial_value: 0
    bit1 :affect_map_modifier_map, initial_value: 0
    bit1 :affect_map_key_syms, initial_value: 0
    bit1 :affect_map_key_types, initial_value: 0
    bit8 :affect_map_null_pad, value: 0
    # mapping mappings from wireshark, uint16 total size
    # .... .... .... ...0 = KeyTypes: False
    # .... .... .... ..0. = KeySyms: False
    # .... .... .... .0.. = ModifierMap: False
    # .... .... .... 0... = ExplicitComponents: False
    # .... .... ...0 .... = KeyActions: False
    # .... .... ..0. .... = KeyBehaviors: False
    # .... .... .0.. .... = VirtualMods: False
    # .... .... 0... .... = VirtualModMap: False
    bit1 :map_virtual_mod_map, initial_value: 0
    bit1 :map_virtual_mods, initial_value: 0
    bit1 :map_key_behaviors, initial_value: 0
    bit1 :map_key_actions, initial_value: 0
    bit1 :map_explicit_components, initial_value: 0
    bit1 :map_modifier_map, initial_value: 0
    bit1 :map_key_syms, initial_value: 0
    bit1 :map_key_types, initial_value: 0
    bit8 :map_null_pad, value: 0
    # affect_new_keyboard mappings from wireshark, uint16 total size
    # .... .... .... ...0 = Keycodes: False
    # .... .... .... ..0. = Geometry: False
    # .... .... .... .0.. = DeviceID: False
    bit5 :affect_new_keyboard_null_pad, value: 0, onlyif: -> { affect_which_new_keyboard_notify == 1 } # may be others but thats all thats observed and implemented at this point
    bit1 :affect_new_keyboard_device_id, initial_value: 0, onlyif: -> { affect_which_new_keyboard_notify == 1 } # may be others but thats all thats observed and implemented at this point
    bit1 :affect_new_keyboard_geometry, initial_value: 0, onlyif: -> { affect_which_new_keyboard_notify == 1 } # may be others but thats all thats observed and implemented at this point
    bit1 :affect_new_keyboard_key_codes, initial_value: 0, onlyif: -> { affect_which_new_keyboard_notify == 1 } # may be others but thats all thats observed and implemented at this point
    bit8 :affect_new_keyboard_null_pad2, value: 0, onlyif: -> { affect_which_new_keyboard_notify == 1 } # may be others but thats all thats observed and implemented at this point
    # new_keyboard_details mappings from wireshark, uint16 total size
    # .... .... .... ...0 = Keycodes: False
    # .... .... .... ..0. = Geometry: False
    # .... .... .... .0.. = DeviceID: False
    bit5 :new_keyboard_details_null_pad, value: 0, onlyif: -> { affect_which_new_keyboard_notify == 1 } # may be others but thats all thats observed and implemented at this point
    bit1 :new_keyboard_details_device_id, initial_value: 0, onlyif: -> { affect_which_new_keyboard_notify == 1 } # may be others but thats all thats observed and implemented at this point
    bit1 :new_keyboard_details_geometry, initial_value: 0, onlyif: -> { affect_which_new_keyboard_notify == 1 } # may be others but thats all thats observed and implemented at this point
    bit1 :new_keyboard_details_key_codes, initial_value: 0, onlyif: -> { affect_which_new_keyboard_notify == 1 } # may be others but thats all thats observed and implemented at this point
    bit8 :new_keyboard_details_null_pad2, value: 0, onlyif: -> { affect_which_new_keyboard_notify == 1 } # may be others but thats all thats observed and implemented at this point
  end

  # https://xcb.freedesktop.org/manual/structxcb__query__keymap__request__t.html
  class X11QueryKeyMapRequest < BinData::Record
    endian :little
    uint8 :opcode, value: 44 # QueryKeymap
    uint8 :pad
    uint16 :request_length, value: -> { num_bytes / 4 }
  end

  # https://xcb.freedesktop.org/manual/structxcb__query__keymap__reply__t.html
  class X11QueryKeyMapResponse < BinData::Record
    endian :little
    uint8 :reply
    uint8 :pad
    uint16 :sequence_number
    uint32 :response_length
    # byte sequence
    uint8_array :data, initial_length: 32
  end

  # https://xcb.freedesktop.org/manual/structxcb__xkb__bell__request__t.html
  class X11BellRequest < BinData::Record
    endian :little
    uint8 :xkeyboard_id # opcode
    uint8 :extension_minor, value: 3 # Bell
    uint16 :request_length, value: -> { num_bytes / 4 }
    uint16 :device_spec, value: 256 # XXX does this come from elsewhere?
    uint16 :bell_class, value: 768
    uint16 :bell_id, value: 1024
    uint8 :percent, initial_value: 50 # xxx do we want to change this?
    uint8 :force_sound, initial_value: 0 # 0 = false, 1 true?
    uint8 :sound_only, initial_value: 0 # 0 = false, 1 true?
    uint8 :pad0
    uint16 :pitch, initial_value: 0
    uint16 :duration, initial_value: 0
    uint16 :pad1
    uint32 :name, initial_value: 814 # XXX do we see this elsewhere?
    uint32 :window
  end
end
