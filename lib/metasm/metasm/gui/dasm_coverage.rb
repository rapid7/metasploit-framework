#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

module Metasm
module Gui
class CoverageWidget < DrawableWidget
	attr_accessor :dasm, :sections, :pixel_w, :pixel_h

	# TODO wheel -> zoom, dragdrop -> scroll?(zoomed)
	def initialize_widget(dasm, parent_widget)
		@dasm = dasm
		@parent_widget = parent_widget

		@curaddr = 0
		@pixel_w = @pixel_h = 2	# use a font ?
		@sections = []
		@section_x = []
		@slave = nil	# another dasmwidget whose curaddr is kept sync

		@default_color_association = { :caret => :yellow, :caret_col => :darkyellow,
			:background => :palegrey, :code => :red, :data => :blue }
	end

	def click(x, y)
		x, y = x.to_i - 1, y.to_i
		@sections.zip(@section_x).each { |(a, l, seq), (sx, sxe)|
			if x >= sx and x < sxe+@pixel_w
				@curaddr = a + (x-sx)/@pixel_w*@byte_per_col + (y/@pixel_h-@spacing)*@byte_per_col/@col_height
				@slave.focus_addr(@curaddr) if @slave rescue @slave=nil
				redraw
				break
			end
		}
	end

	def doubleclick(x, y)
		click(x, y)
		cw = @parent_widget.clone_window(@curaddr, :listing)
		@slave = cw.dasm_widget
		@slave.focus_changed_callback = lambda { redraw rescue @slave.focus_changed_callback = nil }
	end
	alias rightclick doubleclick

	def mouse_wheel(dir, x, y)
		# TODO zoom ?
		case dir
		when :up
		when :down
		end
	end

	def paint
		@curaddr = @slave.curaddr if @slave and @slave.curaddr rescue @slave=nil

		@spacing = 4	# pixels left for borders / inter-section

		@col_height = height/@pixel_h - 2*@spacing	# pixels per column
		@col_height = 1 if @col_height < 1

		cols = width/@pixel_w - 2*@spacing
		cols -= (@sections.length-1) * (@spacing+1)	# space+1: last col of each section may be only 1byte long
		cols = 64 if cols < 64

		# find how much bytes we must stuff per pixel so that it fits in the window
		bytes = @sections.map { |a, l, seq| l }.inject(0) { |a, b| a+b }
		@byte_per_col = (bytes / cols + @col_height) / @col_height * @col_height
		@byte_per_col = @col_height if @byte_per_col < @col_height

		x = @spacing*@pixel_w
		ybase = @spacing*@pixel_h

		# draws a rectangle covering h1 to h2 in y, of width w
		# advances x as needed
		draw_rect = lambda { |h1, h2, rw|
			h2 += 1
			draw_rectangle(x, ybase+@pixel_h*h1, @pixel_w*rw, @pixel_h*(h2-h1))
			rw -= 1 if h2 != @col_height
			x += rw*@pixel_w
		}

		# draws rectangles to cover o1 to o2
		draw = lambda { |o1, o2|
			next if o1 > o2
			o1_ = o1

			o1 /= @byte_per_col / @col_height
			o2 /= @byte_per_col / @col_height

			o11 = o1 % @col_height
			o12 = o1 / @col_height
			o21 = o2 % @col_height
			o22 = o2 / @col_height

			p11 = (o1_ - 1) / (@byte_per_col / @col_height) % @col_height
			x -= @pixel_w if o11 == @col_height-1 and o11 == p11

			if o11 > 0
				draw_rect[o11, (o12 == o22 ? o21 : @col_height-1), 1]
				next if o12 == o22
				o12 += 1
			end

			if o12 < o22
				draw_rect[0, @col_height-1, o22-o12]
			end

			draw_rect[0, o21, 1]
		}

		@section_x = []
		@sections.each { |a, l, seq|
			curoff = 0
			@section_x << [x]
			seq += [[l, l-1]] if not seq[-1] or seq[-1][1] < l	# to draw last data
			seq.each { |o, oe|
				draw_color :data
				draw[curoff, o-1]
				draw_color :code
				draw[o, oe]
				curoff = oe+1
			}
			@section_x.last << x
			x += @spacing*@pixel_w
		}

		@sections.zip(@section_x).each { |(a, l, seq), (sx, sxe)|
			next if @curaddr.kind_of? Integer and not a.kind_of? Integer
			next if @curaddr.kind_of? Expression and not a.kind_of? Expression
			co = @curaddr-a
			if co >= 0 and co < l
				draw_color :caret_col
				x = sx + (co/@byte_per_col)*@pixel_w
				draw_rect[-@spacing, -1, 1]
				draw_rect[@col_height, @col_height+@spacing, 1]
				draw_color :caret
				y = (co*@col_height/@byte_per_col) % @col_height
				y = (co % @byte_per_col) / (@byte_per_col/@col_height)
				draw_rect[y, y, 1]
			end
		}
	end

	def get_cursor_pos
		@curaddr
	end

	def set_cursor_pos(p)
		@curaddr = p
		@slave.focus_addr(@curaddr) if @slave rescue @slave=nil
		redraw
	end

	# focus on addr
	# returns true on success (address exists)
	def focus_addr(addr)
		return if not addr = @parent_widget.normalize(addr) or not @dasm.get_section_at(addr)
		@curaddr = addr
		@slave.focus_addr(@curaddr) if @slave rescue @slave=nil
		gui_update
		true
	end

	# returns the address of the data under the cursor
	def current_address
		@curaddr
	end

	def gui_update
		# ary of section [addr, len, codespan]
		# codespan is an ary of [code_off_start, code_off_end] (sorted by off)
		@sections = @dasm.sections.map { |a, ed|
			a = Expression[a].reduce
			l = ed.length
			if a.kind_of? Integer
				l += a % 32
				a -= a % 32
			end
			acc = []
			# stuff with addr-section_addr is to handle non-numeric section addrs (eg elf ET_REL)
			@dasm.decoded.keys.map { |da| da-a rescue nil }.grep(Integer).grep(0..l).sort.each { |o|
				next if not da = @dasm.di_at(a+o)
				oe = o + da.bin_length
				if acc[-1] and acc[-1][1] >= o
					# handle di overlapping
					acc[-1][1] = oe if acc[-1][1] < oe
				else
					acc << [o, oe]
				end
			}
			[a, l, acc]
		}
		@sections = @sections.sort if @sections.all? { |a, l, s| a.kind_of? Integer }
		redraw
	end
end
end
end
