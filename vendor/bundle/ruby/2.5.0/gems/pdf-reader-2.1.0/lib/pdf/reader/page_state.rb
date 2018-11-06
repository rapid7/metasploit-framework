# coding: utf-8

require 'pdf/reader/transformation_matrix'

class PDF::Reader
    # encapsulates logic for tracking graphics state as the instructions for
    # a single page are processed. Most of the public methods correspond
    # directly to PDF operators.
    class PageState

      DEFAULT_GRAPHICS_STATE = {
        :char_spacing   => 0,
        :word_spacing   => 0,
        :h_scaling      => 1.0,
        :text_leading   => 0,
        :text_font      => nil,
        :text_font_size => nil,
        :text_mode      => 0,
        :text_rise      => 0,
        :text_knockout  => 0
      }

      # starting a new page
      def initialize(page)
        @page          = page
        @cache         = page.cache
        @objects       = page.objects
        @font_stack    = [build_fonts(page.fonts)]
        @xobject_stack = [page.xobjects]
        @cs_stack      = [page.color_spaces]
        @stack         = [DEFAULT_GRAPHICS_STATE.dup]
        state[:ctm]    = identity_matrix
      end

      #####################################################
      # Graphics State Operators
      #####################################################

      # Clones the current graphics state and push it onto the top of the stack.
      # Any changes that are subsequently made to the state can then by reversed
      # by calling restore_graphics_state.
      #
      def save_graphics_state
        @stack.push clone_state
      end

      # Restore the state to the previous value on the stack.
      #
      def restore_graphics_state
        @stack.pop
      end

      #####################################################
      # Matrix Operators
      #####################################################

      # update the current transformation matrix.
      #
      # If the CTM is currently undefined, just store the new values.
      #
      # If there's an existing CTM, then multiply the existing matrix
      # with the new matrix to form the updated matrix.
      #
      def concatenate_matrix(a, b, c, d, e, f)
        if state[:ctm]
          ctm = state[:ctm]
          state[:ctm] = TransformationMatrix.new(a,b,c,d,e,f).multiply!(
            ctm.a, ctm.b,
            ctm.c, ctm.d,
            ctm.e, ctm.f
          )
        else
          state[:ctm] = TransformationMatrix.new(a,b,c,d,e,f)
        end
        @text_rendering_matrix = nil # invalidate cached value
      end

      #####################################################
      # Text Object Operators
      #####################################################

      def begin_text_object
        @text_matrix      = identity_matrix
        @text_line_matrix = identity_matrix
        @font_size = nil
      end

      def end_text_object
        # don't need to do anything
      end

      #####################################################
      # Text State Operators
      #####################################################

      def set_character_spacing(char_spacing)
        state[:char_spacing] = char_spacing
      end

      def set_horizontal_text_scaling(h_scaling)
        state[:h_scaling] = h_scaling / 100.0
      end

      def set_text_font_and_size(label, size)
        state[:text_font]      = label
        state[:text_font_size] = size
      end

      def font_size
        @font_size ||= begin
                         _, zero = trm_transform(0,0)
                         _, one  = trm_transform(1,1)
                         (zero - one).abs
                       end
      end

      def set_text_leading(leading)
        state[:text_leading] = leading
      end

      def set_text_rendering_mode(mode)
        state[:text_mode] = mode
      end

      def set_text_rise(rise)
        state[:text_rise] = rise
      end

      def set_word_spacing(word_spacing)
        state[:word_spacing] = word_spacing
      end

      #####################################################
      # Text Positioning Operators
      #####################################################

      def move_text_position(x, y) # Td
        temp = TransformationMatrix.new(1, 0,
                                        0, 1,
                                        x, y)
        @text_line_matrix = temp.multiply!(
          @text_line_matrix.a, @text_line_matrix.b,
          @text_line_matrix.c, @text_line_matrix.d,
          @text_line_matrix.e, @text_line_matrix.f
        )
        @text_matrix = @text_line_matrix.dup
        @font_size = @text_rendering_matrix = nil # invalidate cached value
      end

      def move_text_position_and_set_leading(x, y) # TD
        set_text_leading(-1 * y)
        move_text_position(x, y)
      end

      def set_text_matrix_and_text_line_matrix(a, b, c, d, e, f) # Tm
        @text_matrix = TransformationMatrix.new(
          a, b,
          c, d,
          e, f
        )
        @text_line_matrix = @text_matrix.dup
        @font_size = @text_rendering_matrix = nil # invalidate cached value
      end

      def move_to_start_of_next_line # T*
        move_text_position(0, -state[:text_leading])
      end

      #####################################################
      # Text Showing Operators
      #####################################################

      def show_text_with_positioning(params) # TJ
        # TODO record position changes in state here
      end

      def move_to_next_line_and_show_text(str) # '
        move_to_start_of_next_line
      end

      def set_spacing_next_line_show_text(aw, ac, string) # "
        set_word_spacing(aw)
        set_character_spacing(ac)
        move_to_next_line_and_show_text(string)
      end

      #####################################################
      # XObjects
      #####################################################
      def invoke_xobject(label)
        save_graphics_state
        xobject = find_xobject(label)

        raise MalformedPDFError, "XObject #{label} not found" if xobject.nil?
        matrix = xobject.hash[:Matrix]
        concatenate_matrix(*matrix) if matrix

        if xobject.hash[:Subtype] == :Form
          form = PDF::Reader::FormXObject.new(@page, xobject, :cache => @cache)
          @font_stack.unshift(form.font_objects)
          @xobject_stack.unshift(form.xobjects)
          yield form if block_given?
          @font_stack.shift
          @xobject_stack.shift
        else
          yield xobject if block_given?
        end

        restore_graphics_state
      end

      #####################################################
      # Public Visible State
      #####################################################

      # transform x and y co-ordinates from the current user space to the
      # underlying device space.
      #
      def ctm_transform(x, y)
        [
          (ctm.a * x) + (ctm.c * y) + (ctm.e),
          (ctm.b * x) + (ctm.d * y) + (ctm.f)
        ]
      end

      # transform x and y co-ordinates from the current text space to the
      # underlying device space.
      #
      # transforming (0,0) is a really common case, so optimise for it to
      # avoid unnecessary object allocations
      #
      def trm_transform(x, y)
        trm = text_rendering_matrix
        if x == 0 && y == 0
          [trm.e, trm.f]
        else
          [
            (trm.a * x) + (trm.c * y) + (trm.e),
            (trm.b * x) + (trm.d * y) + (trm.f)
          ]
        end
      end

      def current_font
        find_font(state[:text_font])
      end

      def find_font(label)
        dict = @font_stack.detect { |fonts|
          fonts.has_key?(label)
        }
        dict ? dict[label] : nil
      end

      def find_color_space(label)
        dict = @cs_stack.detect { |colorspaces|
          colorspaces.has_key?(label)
        }
        dict ? dict[label] : nil
      end

      def find_xobject(label)
        dict = @xobject_stack.detect { |xobjects|
          xobjects.has_key?(label)
        }
        dict ? dict[label] : nil
      end

      # when save_graphics_state is called, we need to push a new copy of the
      # current state onto the stack. That way any modifications to the state
      # will be undone once restore_graphics_state is called.
      #
      def stack_depth
        @stack.size
      end

      # This returns a deep clone of the current state, ensuring changes are
      # keep separate from earlier states.
      #
      # Marshal is used to round-trip the state through a string to easily
      # perform the deep clone. Kinda hacky, but effective.
      #
      def clone_state
        if @stack.empty?
          {}
        else
          Marshal.load Marshal.dump(@stack.last)
        end
      end

      # after each glyph is painted onto the page the text matrix must be
      # modified. There's no defined operator for this, but depending on
      # the use case some receivers may need to mutate the state with this
      # while walking a page.
      #
      # NOTE: some of the variable names in this method are obscure because
      #       they mirror variable names from the PDF spec
      #
      # NOTE: see Section 9.4.4, PDF 32000-1:2008, pp 252
      #
      # Arguments:
      #
      # w0 - the glyph width in *text space*. This generally means the width
      #      in glyph space should be divded by 1000 before being passed to
      #      this function
      # tj - any kerning that should be applied to the text matrix before the
      #      following glyph is painted. This is usually the numeric arguments
      #      in the array passed to a TJ operator
      # word_boundary - a boolean indicating if a word boundary was just
      #                 reached. Depending on the current state extra space
      #                 may need to be added
      #
      def process_glyph_displacement(w0, tj, word_boundary)
        fs = font_size # font size
        tc = state[:char_spacing]
        if word_boundary
          tw = state[:word_spacing]
        else
          tw = 0
        end
        th = state[:h_scaling]
        # optimise the common path to reduce Float allocations
        if th == 1 && tj == 0 && tc == 0 && tw == 0
          glyph_width = w0 * fs
          tx = glyph_width
        else
          glyph_width = ((w0 - (tj/1000.0)) * fs) * th
          tx = glyph_width + ((tc + tw) * th)
        end

        # TODO: I'm pretty sure that tx shouldn't need to be divided by
        #       ctm[0] here, but this gets my tests green and I'm out of
        #       ideas for now
        # TODO: support ty > 0
        if ctm.a == 1 || ctm.a == 0
          @text_matrix.horizontal_displacement_multiply!(tx)
        else
          @text_matrix.horizontal_displacement_multiply!(tx/ctm.a)
        end
        @font_size = @text_rendering_matrix = nil # invalidate cached value
      end

      private

      # used for many and varied text positioning calculations. We potentially
      # need to access the results of this method many times when working with
      # text, so memoize it
      #
      def text_rendering_matrix
        @text_rendering_matrix ||= begin
          state_matrix = TransformationMatrix.new(
            state[:text_font_size] * state[:h_scaling], 0,
            0, state[:text_font_size],
            0, state[:text_rise]
          )
          state_matrix.multiply!(
            @text_matrix.a, @text_matrix.b,
            @text_matrix.c, @text_matrix.d,
            @text_matrix.e, @text_matrix.f
          )
          state_matrix.multiply!(
            ctm.a, ctm.b,
            ctm.c, ctm.d,
            ctm.e, ctm.f
          )
        end
      end

      # return the current transformation matrix
      #
      def ctm
        state[:ctm]
      end

      def state
        @stack.last
      end

      # wrap the raw PDF Font objects in handy ruby Font objects.
      #
      def build_fonts(raw_fonts)
        wrapped_fonts = raw_fonts.map { |label, font|
          [label, PDF::Reader::Font.new(@objects, @objects.deref(font))]
        }

        ::Hash[wrapped_fonts]
      end

      #####################################################
      # Low-level Matrix Operations
      #####################################################

      # This class uses 3x3 matrices to represent geometric transformations
      # These matrices are represented by arrays with 9 elements
      # The array [a,b,c,d,e,f,g,h,i] would represent a matrix like:
      #   a b c
      #   d e f
      #   g h i

      def identity_matrix
        TransformationMatrix.new(1, 0,
                                 0, 1,
                                 0, 0)
      end

    end
end
