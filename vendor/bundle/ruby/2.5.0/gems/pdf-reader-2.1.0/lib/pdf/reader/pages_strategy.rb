# coding: utf-8

################################################################################
#
# Copyright (C) 2006 Peter J Jones (pjones@pmade.com)
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

class PDF::Reader
  ################################################################################
  # == Text Callbacks
  #
  # - end_text_object
  # - move_to_start_of_next_line
  # - set_character_spacing
  # - move_text_position
  # - move_text_position_and_set_leading
  # - set_text_font_and_size
  # - show_text
  # - show_text_with_positioning
  # - set_text_leading
  # - set_text_matrix_and_text_line_matrix
  # - set_text_rendering_mode
  # - set_text_rise
  # - set_word_spacing
  # - set_horizontal_text_scaling
  # - move_to_next_line_and_show_text
  # - set_spacing_next_line_show_text
  #
  # == Graphics Callbacks
  # - close_fill_stroke
  # - fill_stroke
  # - close_fill_stroke_with_even_odd
  # - fill_stroke_with_even_odd
  # - begin_marked_content_with_pl
  # - begin_inline_image
  # - begin_marked_content
  # - begin_text_object
  # - append_curved_segment
  # - concatenate_matrix
  # - set_stroke_color_space
  # - set_nonstroke_color_space
  # - set_line_dash
  # - set_glyph_width
  # - set_glyph_width_and_bounding_box
  # - invoke_xobject
  # - define_marked_content_with_pl
  # - end_inline_image
  # - end_marked_content
  # - fill_path_with_nonzero
  # - fill_path_with_nonzero
  # - fill_path_with_even_odd
  # - set_gray_for_stroking
  # - set_gray_for_nonstroking
  # - set_graphics_state_parameters
  # - close_subpath
  # - set_flatness_tolerance
  # - begin_inline_image_data
  # - set_line_join_style
  # - set_line_cap_style
  # - set_cmyk_color_for_stroking,
  # - set_cmyk_color_for_nonstroking
  # - append_line
  # - begin_new_subpath
  # - set_miter_limit
  # - define_marked_content_point
  # - end_path
  # - save_graphics_state
  # - restore_graphics_state
  # - append_rectangle
  # - set_rgb_color_for_stroking
  # - set_rgb_color_for_nonstroking
  # - set_color_rendering_intent
  # - close_and_stroke_path
  # - stroke_path
  # - set_color_for_stroking
  # - set_color_for_nonstroking
  # - set_color_for_stroking_and_special
  # - set_color_for_nonstroking_and_special
  # - paint_area_with_shading_pattern
  # - append_curved_segment_initial_point_replicated
  # - set_line_width
  # - set_clipping_path_with_nonzero
  # - set_clipping_path_with_even_odd
  # - append_curved_segment_final_point_replicated
  #
  class PagesStrategy # :nodoc:
    OPERATORS = {
      'b'   => :close_fill_stroke,
      'B'   => :fill_stroke,
      'b*'  => :close_fill_stroke_with_even_odd,
      'B*'  => :fill_stroke_with_even_odd,
      'BDC' => :begin_marked_content_with_pl,
      'BI'  => :begin_inline_image,
      'BMC' => :begin_marked_content,
      'BT'  => :begin_text_object,
      'BX'  => :begin_compatibility_section,
      'c'   => :append_curved_segment,
      'cm'  => :concatenate_matrix,
      'CS'  => :set_stroke_color_space,
      'cs'  => :set_nonstroke_color_space,
      'd'   => :set_line_dash,
      'd0'  => :set_glyph_width,
      'd1'  => :set_glyph_width_and_bounding_box,
      'Do'  => :invoke_xobject,
      'DP'  => :define_marked_content_with_pl,
      'EI'  => :end_inline_image,
      'EMC' => :end_marked_content,
      'ET'  => :end_text_object,
      'EX'  => :end_compatibility_section,
      'f'   => :fill_path_with_nonzero,
      'F'   => :fill_path_with_nonzero,
      'f*'  => :fill_path_with_even_odd,
      'G'   => :set_gray_for_stroking,
      'g'   => :set_gray_for_nonstroking,
      'gs'  => :set_graphics_state_parameters,
      'h'   => :close_subpath,
      'i'   => :set_flatness_tolerance,
      'ID'  => :begin_inline_image_data,
      'j'   => :set_line_join_style,
      'J'   => :set_line_cap_style,
      'K'   => :set_cmyk_color_for_stroking,
      'k'   => :set_cmyk_color_for_nonstroking,
      'l'   => :append_line,
      'm'   => :begin_new_subpath,
      'M'   => :set_miter_limit,
      'MP'  => :define_marked_content_point,
      'n'   => :end_path,
      'q'   => :save_graphics_state,
      'Q'   => :restore_graphics_state,
      're'  => :append_rectangle,
      'RG'  => :set_rgb_color_for_stroking,
      'rg'  => :set_rgb_color_for_nonstroking,
      'ri'  => :set_color_rendering_intent,
      's'   => :close_and_stroke_path,
      'S'   => :stroke_path,
      'SC'  => :set_color_for_stroking,
      'sc'  => :set_color_for_nonstroking,
      'SCN' => :set_color_for_stroking_and_special,
      'scn' => :set_color_for_nonstroking_and_special,
      'sh'  => :paint_area_with_shading_pattern,
      'T*'  => :move_to_start_of_next_line,
      'Tc'  => :set_character_spacing,
      'Td'  => :move_text_position,
      'TD'  => :move_text_position_and_set_leading,
      'Tf'  => :set_text_font_and_size,
      'Tj'  => :show_text,
      'TJ'  => :show_text_with_positioning,
      'TL'  => :set_text_leading,
      'Tm'  => :set_text_matrix_and_text_line_matrix,
      'Tr'  => :set_text_rendering_mode,
      'Ts'  => :set_text_rise,
      'Tw'  => :set_word_spacing,
      'Tz'  => :set_horizontal_text_scaling,
      'v'   => :append_curved_segment_initial_point_replicated,
      'w'   => :set_line_width,
      'W'   => :set_clipping_path_with_nonzero,
      'W*'  => :set_clipping_path_with_even_odd,
      'y'   => :append_curved_segment_final_point_replicated,
      '\''  => :move_to_next_line_and_show_text,
      '"'   => :set_spacing_next_line_show_text,
    }
  end
  ################################################################################
end
################################################################################
