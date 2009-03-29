#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'gtk2'

module Metasm
module GtkGui
class AsmListingWidget < Gtk::HBox
	attr_accessor :hl_word

	# construction method
	def initialize(dasm, parent_widget)
		@dasm = dasm
		@parent_widget = parent_widget
		@arrows = []	# array of [linefrom, lineto] (may be :up or :down for offscreen)
		@line_address = {}
		@line_text = {}
		@hl_word = nil
		@caret_x = @caret_y = 0	# caret position in characters coordinates (column/line)
		@oldcaret_x = @oldcaret_y = 42
		@layout = Pango::Layout.new Gdk::Pango.context
		@color = {}

		super()

		@arrows_widget = Gtk::DrawingArea.new
		@listing_widget = Gtk::DrawingArea.new
		@vscroll = Gtk::VScrollbar.new
		pack_start @arrows_widget, false, false
		pack_start @listing_widget
		pack_end @vscroll, false, false
		# TODO listing hscroll (viewport?)

		@arrows_widget.set_size_request 40, 0	# TODO resizer
		ks = @dasm.sections.keys.grep(Integer)
		@vscroll.adjustment.lower = ks.min
		@vscroll.adjustment.upper = ks.max + @dasm.sections[ks.max].length
		@vscroll.adjustment.step_increment = 1
		@vscroll.adjustment.page_increment = 10
		@vscroll.adjustment.value = @dasm.prog_binding['entrypoint'] || @vscroll.adjustment.lower
		set_font 'courier 10'

		# receive mouse/kbd events
		@listing_widget.set_events Gdk::Event::ALL_EVENTS_MASK
		set_can_focus true

		# callbacks
		@arrows_widget.signal_connect('expose_event') { paint_arrows ; true }
		@listing_widget.signal_connect('expose_event') { paint_listing ; true }
		@listing_widget.signal_connect('button_press_event') { |w, ev|
			case ev.event_type
			when Gdk::Event::Type::BUTTON_PRESS
				case ev.button
				when 1; click(ev)
				end
			when Gdk::Event::Type::BUTTON2_PRESS
				case ev.button
				when 1; doubleclick(ev)
				end
			end
		}
		@listing_widget.signal_connect('size_allocate') { |w, alloc| # resize
			lines = alloc.height / @font_height
			cols = alloc.width / @font_width
			@caret_y = lines-1 if @caret_y >= lines
			@caret_x = cols-1 if @caret_x >= cols
			@vscroll.adjustment.page_increment = lines/2
		}
		@vscroll.adjustment.signal_connect('value_changed') { |adj|
			# align on @decoded boundary
			addr = adj.value.to_i
			if off = (0..16).find { |off_| di = @dasm.decoded[addr-off_] and di.respond_to? :bin_length and di.bin_length > off_ } and off != 0
				@vscroll.adjustment.value = addr-off
			else
				@line_address.clear	# make paint_listing call update_caret when done (hl_word etc)
				redraw
			end
		}
		signal_connect('key_press_event') { |w, ev| # keyboard
			keypress(ev)
		}
		signal_connect('scroll_event') { |w, ev| # mouse wheel
			mouse_wheel(ev)
		}
		signal_connect('realize') { # one-time initialize
			# raw color declaration
			{ :white => 'fff', :palegrey => 'ddd', :black => '000', :grey => '444',
			  :red => 'f00', :darkred => '800', :palered => 'fcc',
			  :green => '0f0', :darkgreen => '080', :palegreen => 'cfc',
			  :blue => '00f', :darkblue => '008', :paleblue => 'ccf',
			  :yellow => 'ff0', :darkyellow => '440', :paleyellow => 'ffc',
			}.each { |tag, val|
				@color[tag] = Gdk::Color.new(*val.unpack('CCC').map { |c| (c.chr*4).hex })
			}
			# register colors
			@color.each_value { |c| window.colormap.alloc_color(c, true, true) }

			# map functionnality => color
			set_color_association :comment => :darkblue, :label => :darkgreen, :text => :black,
			  :instruction => :black, :address => :blue, :caret => :black,
			  :listing_bg => :white, :cursorline_bg => :paleyellow, :hl_word => :palered,
			  :arrows_bg => :palegrey,
			  :arrow_up => :darkblue, :arrow_dn => :darkyellow, :arrow_hl => :red
		}
	end

	#
	# methods used as Gtk callbacks
	#

	# TODO right click
	def click(ev)
		@caret_x = (ev.x-1).to_i / @font_width
		@caret_y = ev.y.to_i / @font_height
		update_caret
	end

	def doubleclick(ev)
		@parent_widget.focus_addr(@hl_word)
	end

	def mouse_wheel(ev)
		case ev.direction
		when Gdk::EventScroll::Direction::UP
			# TODO scroll up exactly win_height/2 lines
			# at least cache page_down addresses
			@vscroll.adjustment.value -= @vscroll.adjustment.page_increment
			true
		when Gdk::EventScroll::Direction::DOWN
			pgdown = @line_address[@line_address.keys.max.to_i/2]
			pgdown = @vscroll.adjustment.value + @vscroll.adjustment.page_increment if pgdown == -1
			@vscroll.adjustment.value = pgdown
			true
		end
	end

	# renders the disassembler in the @listing_widget using @vscroll.adjustment.value
	# creates the @arrows needed by #paint_arrows
	def paint_listing
		w = @listing_widget.window
		gc = Gdk::GC.new(w)

		a = @listing_widget.allocation
		w_w, w_h = a.x + a.width, a.y + a.height

		# draw caret line background
		gc.set_foreground @color[:cursorline_bg]
		w.draw_rectangle(gc, true, 0, @caret_y*@font_height, w_w, @font_height)

		# TODO scroll line-by-line when an addr is displayed on multiple lines (eg labels/comments)
		# TODO selection & current word hilight
		curaddr = @vscroll.adjustment.value.to_i

		want_update_caret = true if @line_address == {}

		# map lineno => adress shown
		@line_address = Hash.new(-1)
		# map lineno => raw text
		@line_text = Hash.new('')

		# current line text buffer
		fullstr = ''
		# current line number
		line = 0
		# current window position
		x = 1
		y = 0

		# list of arrows to draw ([addr_from, addr_to])
		arrows_addr = []

		# renders a string at current cursor position with a color
		# must not include newline
		render = lambda { |str, color|
			# function ends when we write under the bottom of the listing
			next if y >= w_h or x >= w_w
			fullstr << str
			# TODO selection
			if @hl_word
				stmp = str
				pre_x = 0
				while stmp =~ /^(.*?)(\b#{Regexp.escape @hl_word}\b)/
					s1, s2 = $1, $2
					@layout.text = s1
					pre_x += @layout.pixel_size[0]
					@layout.text = s2
					hl_x = @layout.pixel_size[0]
					gc.set_foreground @color[:hl_word]
					w.draw_rectangle(gc, true, x+pre_x, y, hl_x, @font_height)
					pre_x += hl_x
					stmp = stmp[s1.length+s2.length..-1]
				end
			end
			@layout.text = str
			gc.set_foreground @color[color]
			w.draw_layout(gc, x, y, @layout)
			x += @layout.pixel_size[0]
		}
		# newline: current line is fully rendered, update @line_address/@line_text etc
		nl = lambda {
			next if y >= w_h
			@line_text[line] = fullstr
			@line_address[line] = curaddr
			fullstr = ''
			line += 1
			x = 1
			y += @font_height
		}

		invb = @dasm.prog_binding.invert

		# draw text until screen is full
		# builds arrows_addr with addresses
		while y < w_h
			if di = @dasm.decoded[curaddr] and di.kind_of? DecodedInstruction
				# a decoded instruction : check if it's a block start
				if di.block.list.first == di
					# render dump_block_header, add a few colors
					b_header = '' ; @dasm.dump_block_header(di.block) { |l| b_header << l ; b_header << ?\n if b_header[-1] != ?\n }
					b_header.each { |l| l.chomp!
						col = :comment
						col = :label if l[0, 2] != '//' and l[-1] == ?:
						render[l, col]
						nl[]
					}
					di.block.each_from_samefunc(@dasm) { |addr|
						addr = @dasm.normalize addr
						next if not addr.kind_of? ::Integer or (@dasm.decoded[addr].kind_of? DecodedInstruction and addr + @dasm.decoded[addr].bin_length == curaddr)
						arrows_addr << [addr, curaddr]
					}
				end
				if di.block.list.last == di
					di.block.each_to_samefunc(@dasm) { |addr|
						addr = @dasm.normalize addr
						next if not addr.kind_of? ::Integer or (addr == curaddr + di.bin_length and
								(not di.opcode.props[:saveip] or di.block.to_subfuncret))
						arrows_addr << [curaddr, addr]
					}
				end
				render[Expression[di.address].to_s + '    ', :address]
				render[di.instruction.to_s.ljust(di.comment ? 24 : 0), :instruction]
				render[' ; ' + di.comment.join(' '), :comment] if di.comment
				nl[]

				# instr overlapping
				if off = (1...di.bin_length).find { |off_| @dasm.decoded[curaddr + off_] }
					nl[]
					curaddr += off
					render["// ------ overlap (#{di.bin_length - off}) ------", :comment]
					nl[]
				else
					curaddr += [di.bin_length, 1].max
				end
			elsif curaddr < @vscroll.adjustment.upper and s = @dasm.get_section_at(curaddr) and s[0].ptr < s[0].length
				# TODO real data display (dwords, xrefs, strings..)
				if label = invb[curaddr] and @dasm.xrefs[curaddr]
					render[Expression[curaddr].to_s + '    ', :address]
					render[label + ' ', :label]
				else
					if label
						render[label+':', :label]
						nl[]
					end
					render[Expression[curaddr].to_s + '    ', :address]
				end
				len = 256
				len -= curaddr % 256 if curaddr.kind_of? Integer
				len = (1..len).find { |l| @dasm.xrefs[curaddr+l] or invb[curaddr+l] or s[0].reloc[s[0].ptr+l] } || len
				if s[0].data.length > s[0].ptr
					str = s[0].read(len).unpack('C*')
					s[0].ptr -= len
					if @dasm.xrefs[curaddr] or rel = s[0].reloc[s[0].ptr] # or (curaddr & 3 == 0 and (len = 4))
						len = Expression::INT_SIZE[rel.type] if rel
						comment = []
						@dasm.each_xref(curaddr) { |xref|
							len = xref.len if xref.len
							comment << " #{xref.type}#{xref.len}:#{Expression[xref.origin]}" if xref.origin
						}
						comment = nil if comment.empty?
						len = 1 if (len != 2 and len != 4) or len < 1
						dat = "#{%w[x db dw x dd][len]} #{Expression[s[0].decode_imm("u#{len*8}".to_sym, @dasm.cpu.endianness)]}"
						aoff = len
					elsif rep = str.inject(0) { |rep_, c|
						case c
						when str[0]; rep_+1
						else break rep_
						end
					} and rep > 4
						dat = "db #{Expression[rep]} dup(#{Expression[str[0]]})"
						aoff = rep
					elsif asc = str.inject('') { |asc_, c|
						case c
						when 0x20..0x7e; asc_ << c
						else break asc_
						end
					} and asc.length > 3
						dat = "db #{asc.inspect}"
						aoff = asc.length
					else
						dat = "db #{Expression[str[0]]}"
						aoff = 1
					end
				else
					if @dasm.xrefs[curaddr]
						comment = []
						@dasm.each_xref(curaddr) { |xref|
							len = xref.len if xref.len
							comment << " #{xref.type}#{xref.len}:#{Expression[xref.origin]}"
						}
						len = 1 if (len != 2 and len != 4) or len < 1
						dat = "#{%w[x db dw x dd][len]} ?"
						aoff = len
					else
						len = [len, s[0].length-s[0].ptr].min
						dat = "#{Expression[len]} dup(?)"
						aoff = len
					end
				end
				render[dat.ljust(comment ? 24 : 0), :instruction]
				render[' ; ' + comment.join(' '), :comment] if comment
				comment = nil
				nl[]
				curaddr += aoff
			else
				nl[]
				curaddr += 1
			end
		end

		# draw caret
		# TODO selection
		gc.set_foreground @color[:caret]
		cx = @caret_x*@font_width+1
		cy = @caret_y*@font_height
		w.draw_line(gc, cx, cy, cx, cy+@font_height-1)

		# convert arrows_addr to @arrows (with line numbers)
		# updates @arrows_widget if @arrows changed
		prev_arrows = @arrows
		addr_line = @line_address.sort.inject({}) { |h, (l, a_)| h.update a_ => l }	# addr => last line (di)
		@arrows = arrows_addr.uniq.sort.map { |from, to|
			[(addr_line[from] || (from < curaddr ? :up : :down)),
			 (addr_line[ to ] || ( to  < curaddr ? :up : :down))]
		}
		@arrows_widget.window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false if prev_arrows != @arrows

		update_caret if want_update_caret
	end

	# draws the @arrows defined in paint_listing
	def paint_arrows
		return if @arrows.empty? or @line_address[@caret_y] == -1
		w = @arrows_widget.window
		gc = Gdk::GC.new(w)
		w_w, w_h = @arrows_widget.allocation.width, @arrows_widget.allocation.height

		slot_alloc = {}	# [y1, y2] => x slot	-- y1 <= y2
		# find a free x slot for the vertical side of the arrow
		max = (w_w-6)/3
		find_free = lambda { |y1, y2|
			y1, y2 = y2, y1 if y2 < y1
			slot_alloc[[y1, y2]] = (0...max).find { |off|
				not slot_alloc.find { |(oy1, oy2), oo|
					# return true if this slot cannot share with off
					next if oo != off	# not same slot => ok
					next if oy1 == y1 and y1 != 0		# same upbound & in window
					next if oy2 == y2 and y2 != w_h-1	# same lowbound & in window
					# check overlapping segment
					(y1 >= oy1 and y1 <= oy2) or
					(y2 >= oy1 and y2 <= oy2) or
					(oy1 >= y1 and oy1 <= y2) or
					(oy2 >= y1 and oy2 <= y2)
				}
			} || (max-1)
		}

		# alloc slots for arrows, starts by the smallest
		arrs = { :arrow_dn => [], :arrow_up => [], :arrow_hl => [] }
		@arrows.sort_by { |from, to|
			if from.kind_of? Numeric and to.kind_of? Numeric
				(from-to).abs
			else
				100000
			end
		}.each { |from, to|
			y1 = case from
			when :up; 0
			when :down; w_h-1
			else from * @font_height + @font_height/2 - 1
			end
			y2 = case to
			when :up; 0
			when :down; w_h-1
			else to * @font_height + @font_height/2 - 1
			end
			if y1 <= y2
				y1 += 2 if y1 != 0
			else
				y1 -= 2 if y1 != w_h-1
			end

			col = :arrow_dn
			col = :arrow_up if y1 > y2
			col = :arrow_hl if @line_address[from] == @line_address[@caret_y] or @line_address[to] == @line_address[@caret_y]
			arrs[col] << [y1, y2, find_free[y1, y2]]
		}

		slot_w = (w_w-4)/slot_alloc.values.uniq.length
		# draw arrows (hl last to overwrite)
		[:arrow_dn, :arrow_up, :arrow_hl].each { |col|
			gc.set_foreground @color[col]
			arrs[col].each { |y1, y2, slot|
				x1 = w_w-1
				x2 = w_w-4 - slot*slot_w - slot_w/2

				w.draw_line(gc, x1, y1, x2, y1) if y1 != 0 and y1 != w_h-1
				w.draw_line(gc, x2, y1, x2, y2)
				w.draw_line(gc, x2, y2, x1, y2) if y2 != 0 and y2 != w_h-1
				w.draw_line(gc, x1, y2, x1-3, y2-3) if y2 != 0 and y2 != w_h-1
				w.draw_line(gc, x1, y2, x1-3, y2+3) if y2 != 0 and y2 != w_h-1
			}
		}
	end

	include Gdk::Keyval
	# keyboard binding
	# basic navigation (arrows, pgup etc)
	# dasm navigation
	#  enter => go to label definition
	#  esc => jump back
	# dasm interaction
	#  c => start disassembling from here
	#  g => prompt for an address to jump to
	#  h => prompt for a C header file to read
	#  n => rename a label
	#  p => pause/play disassembler
	#  x => show xrefs
	#
	def keypress(ev)
		case ev.keyval
		when GDK_Left
			if @caret_x >= 1
				@caret_x -= 1
				update_caret
			end
		when GDK_Up
			if @caret_y > 1 or (@caret_y == 1 and @vscroll.adjustment.value == @vscroll.adjustment.lower)
				@caret_y -= 1
			else
				@vscroll.adjustment.value -= 1
			end
			update_caret
		when GDK_Right
			if @caret_x <= @line_text.values.map { |s| s.length }.max
				@caret_x += 1
				update_caret
			end
		when GDK_Down
			if @caret_y < @line_text.length-2 or (@caret_y < @line_text.length - 1 and @vscroll.adjustment.value == @vscroll.adjustment.upper)
				@caret_y += 1
			else
				off = 1
				if a = @line_address[0] and @dasm.decoded[a].kind_of? DecodedInstruction
					off = @dasm.decoded[a].bin_length
				end
				@vscroll.adjustment.value += off
			end
			update_caret
		when GDK_Page_Up
			@vscroll.adjustment.value -= @vscroll.adjustment.page_increment
			update_caret
		when GDK_Page_Down
			pgdown = @line_address[@line_address.length/2]
			pgdown = @vscroll.adjustment.value + @vscroll.adjustment.page_increment if pgdown == -1
			@vscroll.adjustment.value = pgdown
			update_caret
		when GDK_Home
			@caret_x = 0
			update_caret
		when GDK_End
			@caret_x = @line_text[@caret_y].length
			update_caret

		else
			return @parent_widget.keypress(ev)
		end
		true
	end

	def get_cursor_pos
		[@vscroll.adjustment.value, @caret_x, @caret_y]
	end

	def set_cursor_pos(p)
		@vscroll.adjustment.value, @caret_x, @caret_y = p
		update_caret
	end

	# change the font of the listing
	# arg is a Gtk Fontdescription string (eg 'courier 10')
	def set_font(descr)
		@layout.font_description = Pango::FontDescription.new(descr)
		@layout.text = 'x'
		@font_width, @font_height = @layout.pixel_size
		redraw
	end

	# change the color association
	# arg is a hash function symbol => color symbol
	# color must be allocated
	# check #initialize/sig('realize') for initial function/color list
	def set_color_association(hash)
		hash.each { |k, v| @color[k] = @color[v] }
		@listing_widget.modify_bg Gtk::STATE_NORMAL, @color[:listing_bg]
		@arrows_widget.modify_bg Gtk::STATE_NORMAL, @color[:arrows_bg]
		redraw
	end

	# redraw the whole widget
	def redraw
		return if not @listing_widget.window
		@listing_widget.window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false
		@arrows_widget.window.invalidate  Gdk::Rectangle.new(0, 0, 100000, 100000), false
	end

	# hint that the caret moved
	# redraws the caret, change the hilighted word, redraw if needed
	def update_caret
		return if not l = @line_text[@caret_y]
		word = l[0...@caret_x].to_s[/\w*$/] << l[@caret_x..-1].to_s[/^\w*/]
		word = nil if word == ''
		if @hl_word != word or @oldcaret_y != @caret_y
			@hl_word = word
			redraw
		else
			return if @oldcaret_x == @caret_x and @oldcaret_y == @caret_y
			x = @oldcaret_x*@font_width+1
			y = @oldcaret_y*@font_height
			@listing_widget.window.invalidate Gdk::Rectangle.new(x-1, y, x+1, y+@font_height), false
			x = @caret_x*@font_width+1
			y = @caret_y*@font_height
			@listing_widget.window.invalidate Gdk::Rectangle.new(x-1, y, x+1, y+@font_height), false
			if @arrows.find { |f, t| f == @caret_y or t == @caret_y or f == @oldcaret_y or t == @oldcaret_y }
				@arrows_widget.window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false
			end
		end

		@oldcaret_x = @caret_x
		@oldcaret_y = @caret_y
	end

	# focus on addr
	# addr may be a dasm label, dasm address, dasm address in string form (eg "0DEADBEEFh")
	# may scroll the window
	# returns true on success (address exists)
	def focus_addr(addr)
		if l = @line_address.index(addr) and l < @line_address.keys.max - 4
			@caret_y, @caret_x = @line_address.keys.find_all { |k| @line_address[k] == addr }.max, 0
		elsif addr >= @vscroll.adjustment.lower and addr <= @vscroll.adjustment.upper
			@vscroll.adjustment.value, @caret_x, @caret_y = addr, 0, 0
		else
			return
		end
		update_caret
		true
	end

	# returns the address of the data under the cursor
	def current_address
		@line_address[@caret_y]
	end

	def gui_update
		redraw
	end
end
end
end
