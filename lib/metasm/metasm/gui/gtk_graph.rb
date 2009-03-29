#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'gtk2'

module Metasm
module GtkGui
class Graph
	# one box, has a text, an id, and a list of other boxes to/from
	class Box
		attr_accessor :id, :x, :y, :w, :h
		attr_accessor :to, :from # other boxes linked (arrays)
		attr_accessor :content
		def initialize(id, content=nil)
			@id = id
			@x = @y = @w = @h = 0
			@to, @from = [], []
			@content = content
		end
		def [](a) @content[a] end
		#def inspect ; puts caller ; "#{Expression[@id] rescue @id.inspect}" end
	end

	# TODO
	class MergedBox
		attr_accessor :id, :text, :x, :y, :w, :h
		attr_accessor :to, :from
	end

	attr_accessor :id, :box, :root_addrs, :view_x, :view_y, :keep_split
	def initialize(id)
		@id = id
		@root_addrs = []
		clear
	end

	# empty @box
	def clear
		@box = []
	end

	# link the two boxes (by id)
	def link_boxes(id1, id2)
		raise "unknown index 1 #{id1}" if not b1 = @box.find { |b| b.id == id1 }
		raise "unknown index 2 #{id2}" if not b2 = @box.find { |b| b.id == id2 }
		b1.to   |= [b2]
		b2.from |= [b1]
	end

	# creates a new box, ensures id is not already taken
	def new_box(id, content=nil)
		raise "duplicate id #{id}" if @box.find { |b| b.id == id }
		b = Box.new(id, content)
		@box << b
		b
	end

	# place boxes in a good-looking layout
	def auto_arrange_boxes
		return if @box.empty?

		# groups is an array of box groups
		# all groups are centered on the origin
		groups = @box.map { |b|
			b.x = -b.w/2
			b.y = -b.h/2
			g = Box.new(nil, [b])
			g.x = b.x - 8
			g.y = b.y - 9
			g.w = b.w + 16
			g.h = b.h + 18
			g
		}

		# init group.to/from
		# must always point to something that is in the 'groups' array
		# no self references
		# a box is in one and only one group in 'groups'
		groups.each { |g|
			g.to   = g.content.first.to.map   { |t| groups[@box.index(t)] } - [g]
			g.from = g.content.first.from.map { |f| groups[@box.index(f)] } - [g]
		}

		# walk from a box, fork at each multiple to, chop links to a previous box (loops etc)
		madetree = false
		maketree = lambda { |roots|
			next if madetree
			madetree = true

			maxdepth = {}	# max arc count to reach this box from graph start (excl loop)

			trim = lambda { |g, from|
				# unlink g from (part of) its from
				from.each { |gg| gg.to.delete g }
				g.from -= from
			}

			walk = lambda { |g|
				# score
				parentdepth = g.from.map { |gg| maxdepth[gg] }
				if parentdepth.empty?
					# root
					maxdepth[g] = 0
				elsif parentdepth.include? nil
					# not farthest parent found / loop
					next
				# elsif maxdepth[g] => ?
				else
					maxdepth[g] = parentdepth.max + 1
				end
				g.to.each { |gg| walk[gg] }
			}

			roots.each { |g| trim[g, g.from] }
			roots.each { |g| walk[g] }
			
			# handle loops now (unmarked nodes)
			while unmarked = groups - maxdepth.keys and not unmarked.empty?
				if g = unmarked.find { |g_| g_.from.find { |gg| maxdepth[gg] } }
					# loop head
					trim[g, g.from.find_all { |gg| not maxdepth[gg] }]	# XXX not quite sure for this
					walk[g]
				else
					# disconnected subgraph
					g = unmarked.find { |g_| g_.from.empty? } || unmarked.first
					trim[g, g.from]
					maxdepth[g] = 0
					walk[g]
				end
			end
		}

		# concat all ary boxes into its 1st element, remove trailing groups from 'groups'
		# updates from/to
		merge_groups = lambda { |ary|
			bg = Box.new(nil, [])
			bg.x, bg.y = ary.map { |g| g.x }.min, ary.map { |g| g.y }.min
			bg.w, bg.h = ary.map { |g| g.x+g.w }.max - bg.x, ary.map { |g| g.y+g.h }.max - bg.y
			ary.each { |g|
				bg.content.concat g.content
				bg.to |= g.to
				bg.from |= g.from
			}
			bg.to -= ary
			bg.to.each { |t| t.from = t.from - ary + [bg] }
			bg.from -= ary
			bg.from.each { |f| f.to = f.to - ary + [bg] }
			idx = ary.map { |g| groups.index(g) }.min
			groups = groups - ary
			groups.insert(idx, bg)
			bg
		}

		# move all boxes within group of dx, dy
		move_group = lambda { |g, dx, dy|
			g.content.each { |b| b.x += dx ; b.y += dy }
			g.x += dx ; g.y += dy
		}

		align_hz = lambda { |ary|
			nx = ary.map { |g| g.w }.inject(0) { |a, b| a+b } / -2
			ary.each { |g|
				move_group[g, nx-g.x, 0]
				nx += g.w
			}
		}
		align_vt = lambda { |ary|
			ny = ary.map { |g| g.h }.inject(0) { |a, b| a+b } / -2
			ary.each { |g|
				move_group[g, 0, ny-g.y]
				ny += g.h
			}
		}

		# scan groups for a column pattern (head has 1 'to' which from == [head])
		group_columns = lambda {
			groups.find { |g|
				next if g.from.length == 1 and g.from.first.to.length == 1
				ary = [g]
				ary << (g = g.to.first) while g.to.length == 1 and g.to.first.from.length == 1
				next if ary.length <= 1
				align_vt[ary]
				merge_groups[ary]
				true
			}
		}

		# scan groups for a line pattern (multiple groups with same to & same from)
		group_lines = lambda { |strict|
			groups.find { |g1|
				ary = g1.from.map { |gg| gg.to }.flatten.uniq.find_all { |gg|
					gg != g1 and
					(gg.from - g1.from).empty? and (g1.from - gg.from).empty? and
					(strict ? ((gg.to - g1.to).empty? and (g1.to - gg.to).empty?) : (g1.to & gg.to).first)
				}
				next if ary.empty?
				ary << g1
				dy = 16*ary.map { |g| g.to.length + g.from.length }.inject { |a, b| a+b }
				ary.each { |g| g.h += dy ; g.y -= dy/2 }
				align_hz[ary]
				if ary.first.to.empty?	# shrink graph if highly dissymetric and to.empty?
					ah = ary.map { |g| g.h }.max
					ary.each { |g|
						move_group[g, 0, (g.h-ah)/2]	# move up
						next if not p = ary[ary.index(g)-1]
						y = [g.y, p.y].min		# shrink width
						h = [g.h, p.h].min
						xp = p.content.map { |b| b.x+b.w if b.y+b.h+8 >= y and b.y-8 <= y+h }.compact.max || p.x+p.w/2
						xg = g.content.map { |b| b.x if b.y+b.h+8 >= y and b.y-8 <= y+h }.compact.min || g.x+g.w/2
						dx = xg-xp-24
						next if dx <= 0
						ary.each { |gg|
							dx = -dx if gg == g
							move_group[gg, dx/2, 0]
						}
						if p.x+p.w > ary.last.x+ary.last.w or ary.first.x > g.x # fix broken centerism
							x = [g.x, ary.first.x].min
							xm = [p.x+p.w, ary.last.x+ary.last.w].max
							ary.each { |gg| move_group[gg, (x+xm)/-2, 0] }
						end
					}
				end
				merge_groups[ary]
				true
			}
		}

		# scan groups for a if/then pattern (1 -> 2 -> 3 & 1 -> 3)
		group_ifthen = lambda { |strict|
			groups.reverse.find { |g|
				next if not g2 = g.to.find { |g2_| (g2_.to.length == 1 and g.to.include?(g2_.to.first)) or
					(not strict and g2_.to.empty?)  }
				next if strict and g2.from != [g] or g.to.length != 2
				g2.h += 16 ; g2.y -= 8
				align_vt[[g, g2]]
				move_group[g2, -g2.x+8, 0]
				merge_groups[[g, g2]]
				true
			}
		}

		# if (a || b) c;
		# the 'else' case handles '&& else', and && is two if/then nested
		group_or = lambda {
			groups.find { |g|
				next if g.to.length != 2
				g2 = g.to[0]
				g2 = g.to[1] if not g2.to.include? g.to[1]
				thn = (g.to & g2.to).first
				next if g2.to.length != 2 or not thn or thn.to.length != 1
				els = (g2.to - [thn]).first
				if thn.to == [els]
					els = nil
				else
					next if els.to != thn.to
					align_hz[[thn, els]]
					thn = merge_groups[[thn, els]]
				end
				thn.h += 16 ; thn.y -= 8
				align_vt[[g, g2, thn]]
				move_group[g2, -g2.x, 0]
				move_group[thn, thn.x-8, 0] if not els
				merge_groups[[g, g2, thn]]
				true
			}
		}


		# loop with exit 1 -> 2, 3 & 2 -> 1
		group_loop = lambda {
			groups.find { |g|
				next if not g2 = g.to.sort_by { |g2_| g2_.h }.find { |g2_| g2_.to == [g] or (g2_.to.empty? and g2_.from == [g]) }
				g2.h += 16
				align_vt[[g, g2]]
				move_group[g2, g2.x-8, 0]
				merge_groups[[g, g2]]
				true
			}
		}

		# same single from or to
		group_halflines = lambda {
			groups.find { |g|
				next if !(ary = g.from.find_all { |gg| gg.to == [g] } and ary.length > 1) and
					!(ary = g.to.find_all { |gg| gg.from == [g] } and ary.length > 1)
				align_hz[ary]
				merge_groups[ary]
				true
			}
		}


		# unknown pattern, group as we can..
		group_other = lambda {
puts 'graph arrange: unknown configuration', groups.map { |g| "#{groups.index(g)} -> #{g.to.map { |t| groups.index(t) }.inspect}" }
			g1 = groups.find_all { |g| g.from.empty? }
			g1 << groups[rand(groups.length)] if g1.empty?
			g2 = g1.map { |g| g.to }.flatten.uniq - g1
			align_vt[g1]
			g1 = merge_groups[g1]
			g1.w += 128 ; g1.x -= 64
			next if g2.empty?
			align_vt[g2]
			g2 = merge_groups[g2]
			g2.w += 128 ; g2.x -= 64

			align_hz[[g1, g2]]
			merge_groups[[g1, g2]]
			true
		}

		# walk graph from roots, cut backward links
		trim_graph = lambda {
			g1 = groups.find_all { |g| g.from.empty? }
			g1 << groups.first if g1.empty?
			cntpre = groups.inject(0) { |cntpre_, g| cntpre_ + g.to.length }
			g1.each { |g| maketree[[g]] }
			cntpost = groups.inject(0) { |cntpre_, g| cntpre_ + g.to.length }
			true if cntpre != cntpost
		}

		# known, clean patterns
		group_clean = lambda {
			group_columns[] or group_lines[true] or group_ifthen[true] or group_loop[] or group_or[]
		}
		# approximations
		group_unclean = lambda {
			group_lines[false] or group_ifthen[false] or group_halflines[] or group_other[]
		}

		nil while groups.length > 1 and (group_clean[] or trim_graph[] or group_unclean[])

		@box.each { |b|
			b.to = b.to.sort_by { |bt| bt.x }
			b.from = b.from.sort_by { |bt| bt.x }
		}
	end
end





class GraphViewWidget < Gtk::HBox
	attr_accessor :hl_word

	def initialize(dasm, parent_widget)
		@dasm = dasm
		@parent_widget = parent_widget
		@hl_word = nil
		@caret_x = @caret_y = @caret_box = nil
		@layout = Pango::Layout.new Gdk::Pango.context
		@color = {}
		@selected_boxes = []
		@shown_boxes = []
		@mousemove_origin = nil
		@curcontext = Graph.new(nil)
		@zoom = 1.0
		# @allgraphs = ?
		# scrollbars ?

		super()

		@drawarea = Gtk::DrawingArea.new
		pack_start @drawarea

		@width = @height = 20

		set_font 'courier 10'

		@drawarea.set_events Gdk::Event::ALL_EVENTS_MASK	# receive click/keys
		set_can_focus true			# receive keys

		@drawarea.signal_connect('expose_event') { paint ; true }
		@drawarea.signal_connect('motion_notify_event') { |w, ev|
			mousemove(ev) if @mousemove_origin
		}
		@drawarea.signal_connect('size_allocate') { |w, ev| @width, @height = ev.width, ev.height }
		signal_connect('button_press_event') { |w, ev|
			case ev.event_type
			when Gdk::Event::BUTTON_PRESS
				case ev.button
				when 1; click(ev)
				when 3; rightclick(ev)
				end
			when Gdk::Event::BUTTON2_PRESS
				doubleclick(ev)
			end
		}
		signal_connect('button_release_event') { |w, ev|
			mouserelease(ev) if @mousemove_origin and ev.button == 1
		}
		signal_connect('scroll_event') { |w, ev|
			mousewheel(ev)
		}
		signal_connect('key_press_event') { |w, ev|
			keypress(ev)
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
			set_color_association :bg => :paleblue, :hlbox_bg => :palegrey, :box_bg => :white,
				:text => :black, :arrow_hl => :red, :comment => :darkblue,
				:instruction => :black, :label => :darkgreen, :caret => :black, :hl_word => :palered,
				:cursorline_bg => :paleyellow, :arrow_cond => :darkgreen, :arrow_uncond => :darkblue
		}
	end

	def find_box_xy(x, y)
		x = @curcontext.view_x+x/@zoom
		y = @curcontext.view_y+y/@zoom
		@shown_boxes.to_a.reverse.find { |b| b.x <= x+@zoom and b.x+b.w >= x and b.y <= y+@zoom and b.y+b.h >= y }
	end

	def mousewheel(ev)
		case ev.direction
		when Gdk::EventScroll::Direction::UP
			if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK
				if @zoom < 100
					oldzoom = @zoom
					@zoom *= 1.1
					@zoom = 1.0 if (@zoom-1.0).abs < 0.05
					@curcontext.view_x += (ev.x / oldzoom - ev.x / @zoom)
					@curcontext.view_y += (ev.y / oldzoom - ev.y / @zoom)
				end
			else
				@curcontext.view_y -= @height/4 / @zoom
			end
			redraw
		when Gdk::EventScroll::Direction::DOWN
			if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK
				if @zoom > 1.0/100
					oldzoom = @zoom
					@zoom /= 1.1
					@zoom = 1.0 if (@zoom-1.0).abs < 0.05
					@curcontext.view_x += (ev.x / oldzoom - ev.x / @zoom)
					@curcontext.view_y += (ev.y / oldzoom - ev.y / @zoom)
				end
			else
				@curcontext.view_y += @height/4 / @zoom
			end
			redraw
		end
	end

	def mousemove(ev)
		return if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK

		dx = (ev.x - @mousemove_origin[0])/@zoom
		dy = (ev.y - @mousemove_origin[1])/@zoom
		@mousemove_origin = [ev.x, ev.y]
		if @selected_boxes.empty?
			@curcontext.view_x -= dx ; @curcontext.view_y -= dy
		else
			@selected_boxes.each { |b| b.x += dx ; b.y += dy }
		end
		redraw
	end

	def mouserelease(ev)
		mousemove(ev)
		if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK
			x1 = @curcontext.view_x + @mousemove_origin[0]/@zoom
			x2 = x1 + (ev.x - @mousemove_origin[0])/@zoom
			x1, x2 = x2, x1 if x1 > x2
			y1 = @curcontext.view_y + @mousemove_origin[1]/@zoom
			y2 = y1 + (ev.y - @mousemove_origin[1])/@zoom
			y1, y2 = y2, y1 if y1 > y2
			@selected_boxes |= @curcontext.box.find_all { |b| b.x >= x1 and b.x + b.w <= x2 and b.y >= y1 and b.y + b.h <= y2 }
			redraw
		end
		@mousemove_origin = nil
	end

	def click(ev)
		@mousemove_origin = [ev.x, ev.y]
		b = find_box_xy(ev.x, ev.y)
		if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK
			if b
				if @selected_boxes.include? b
					@selected_boxes.delete b
				else
					@selected_boxes << b
				end
			end
		elsif b
			@selected_boxes = [b] if not @selected_boxes.include? b
			@caret_box = b
			@caret_x = (@curcontext.view_x+ev.x-b.x*@zoom - 1).to_i / @font_width
			@caret_y = (@curcontext.view_y+ev.y-b.y*@zoom - 1).to_i / @font_height
			update_caret
		else
			@selected_boxes = []
			@caret_box = nil
			#@hl_word = nil
		end
		redraw
	end

	# if the target is a call to a subfunction, open a new window with the graph of this function (popup)
	def rightclick(ev)
		if b = find_box_xy(ev.x, ev.y) and @zoom >= 0.90 and @zoom <= 1.1
			click(ev)
			@mousemove_origin = nil
			popup = Gtk::Window.new
			popup.title = "metasm dasm: #{@hl_word}"
			popwidg = DisasmWidget.new(@dasm, @parent_widget.entrypoints)
			popwidg.terminate
			popup.add popwidg
			popup.set_default_size 500, 500 # XXX find good size
			popup.show_all
			popwidg.focus_addr @hl_word, 1
		end
	end

	def doubleclick(ev)
		if b = find_box_xy(ev.x, ev.y)
			@mousemove_origin = nil
			if @hl_word and @zoom >= 0.90 and @zoom <= 1.1
				@parent_widget.focus_addr(@hl_word)
			else
				@parent_widget.focus_addr b[:addresses].first
			end
		elsif @zoom == 1.0
			zoom_all
		else
			@curcontext.view_x += (ev.x / @zoom - ev.x)
			@curcontext.view_y += (ev.y / @zoom - ev.y)
			@zoom = 1.0
		end
		redraw
	end

	# update the zoom & view_xy to show the whole graph in the window
	def zoom_all
		minx = @curcontext.box.map { |b| b.x }.min.to_i - 10
		miny = @curcontext.box.map { |b| b.y }.min.to_i - 10
		maxx = @curcontext.box.map { |b| b.x + b.w }.max.to_i + 10
		maxy = @curcontext.box.map { |b| b.y + b.h }.max.to_i + 10
		@zoom = [@width.to_f/(maxx-minx), @height.to_f/(maxy-miny)].min
		@zoom = 1.0 if @zoom > 1.0 or (@zoom-1.0).abs < 0.1
		@curcontext.view_x = minx + (maxx-minx-@width/@zoom)/2
		@curcontext.view_y = miny + (maxy-miny-@height/@zoom)/2
		redraw
	end

	def paint
		w = @drawarea.window
		gc = Gdk::GC.new(w)
		w_w, w_h = @width, @height

		# TODO do this somewhere else
		#@curcontext.auto_arrange_boxes if not @curcontext.box.empty? and @curcontext.box.all? { |b| b.x == 0 and b.y == 0 }

		# TODO MergedBoxes

		# arrows
		# draw first to stay under the boxes
		# XXX precalc ?
		@curcontext.box.each { |b|
			b.to.each { |tb|
				paint_arrow(w, gc, b, tb)
			}
		}

		# XXX reorder boxes ? (for zorder) (eg. on focus)
		@shown_boxes = []
		@curcontext.box.each { |b|
			next if b.x >= @curcontext.view_x+w_w/@zoom or b.y >= @curcontext.view_y+w_h/@zoom or b.x+b.w <= @curcontext.view_x or b.y+b.h <= @curcontext.view_y
			@shown_boxes << b

			paint_box(w, gc, b)
		}
	end

	def paint_arrow(w, gc, b1, b2)
		# TODO separate arrows ends by a few pixels (esp incoming vs outgoing)
		x1, y1 = b1.x+b1.w/2-@curcontext.view_x, b1.y+b1.h-@curcontext.view_y
		x2, y2 = b2.x+b2.w/2-@curcontext.view_x, b2.y-1-@curcontext.view_y
		x1 += (-(b1.to.length-1)/2 + b1.to.index(b2)) * 4
		x2 += (-(b2.from.length-1)/2 + b2.from.index(b1)) * 4
		margin = 8
		return if (y1+margin < 0 and y2 < 0) or (y1 > @height/@zoom and y2-margin > @height/@zoom)	# just clip on y
		margin, x1, y1, x2, y2, b1w, b2w = [margin, x1, y1, x2, y2, b1.w, b2.w].map { |v| v*@zoom }


		# gtk wraps coords around 0x8000
		if x1.abs > 0x7000 ; y1 /= x1.abs/0x7000 ; x1 /= x1.abs/0x7000 ; end
		if y1.abs > 0x7000 ; x1 /= y1.abs/0x7000 ; y1 /= y1.abs/0x7000 ; end
		if x2.abs > 0x7000 ; y2 /= x2.abs/0x7000 ; x2 /= x2.abs/0x7000 ; end
		if y2.abs > 0x7000 ; x2 /= y2.abs/0x7000 ; y2 /= y2.abs/0x7000 ; end

		if b1 == @caret_box or b2 == @caret_box
			gc.set_foreground @color[:arrow_hl]
		elsif b1.to.length == 1
			gc.set_foreground @color[:arrow_uncond]
		else
			gc.set_foreground @color[:arrow_cond]
		end
		if margin > 1
			w.draw_line(gc, x1, y1, x1, y1+margin)
			w.draw_line(gc, x2, y2-margin+1, x2, y2)
			w.draw_line(gc, x2-margin/2, y2-margin/2, x2, y2)
			w.draw_line(gc, x2+margin/2, y2-margin/2, x2, y2)
			y1 += margin
			y2 -= margin-1
		end
		if y2+margin >= y1-margin-1
			w.draw_line(gc, x1, y1, x2, y2) if x1 != y1 or x2 != y2
		elsif x1-b1w/2-margin >= x2+b2w/2+margin	# z
			w.draw_line(gc, x1, y1, x1-b1w/2-margin, y1)
			w.draw_line(gc, x1-b1w/2-margin, y1, x2+b2w/2+margin, y2)
			w.draw_line(gc, x2+b2w/2+margin, y2, x2, y2)
			w.draw_line(gc, x1, y1+1, x1-b1w/2-margin, y1+1) # double
			w.draw_line(gc, x1-b1w/2-margin+1, y1, x2+b2w/2+margin+1, y2)
			w.draw_line(gc, x2+b2w/2+margin, y2+1, x2, y2+1)
		elsif x1+b1w/2+margin <= x2-b2w/2-margin	# invert z
			w.draw_line(gc, x1, y1, x1+b1w/2+margin, y1)
			w.draw_line(gc, x1+b1w/2+margin, y1, x2-b2w/2-margin, y2)
			w.draw_line(gc, x2-b2w/2-margin, y2, x2, y2)
			w.draw_line(gc, x1, y1+1, x1+b1w/2+margin, y1+1) # double
			w.draw_line(gc, x1+b1w/2+margin+1, y1, x2-b2w/2-margin+1, y2)
			w.draw_line(gc, x2-b2w/2-margin, y2+1, x2, y2+1)
		else						# turn around
			x = (x1 <= x2 ? [x1-b1w/2-margin, x2-b2w/2-margin].min : [x1+b1w/2+margin, x2+b2w/2+margin].max)
			w.draw_line(gc, x1, y1, x, y1)
			w.draw_line(gc, x, y1, x, y2)
			w.draw_line(gc, x, y2, x2, y2)
			w.draw_line(gc, x1, y1+1, x, y1+1) # double
			w.draw_line(gc, x+1, y1, x+1, y2)
			w.draw_line(gc, x, y2+1, x2, y2+1)
		end
	end

	def paint_box(w, gc, b)
		gc.set_foreground @color[:black]
		w.draw_rectangle(gc, true, (b.x-@curcontext.view_x+3)*@zoom, (b.y-@curcontext.view_y+3)*@zoom, b.w*@zoom, b.h*@zoom)
		if @selected_boxes.include? b
			gc.set_foreground @color[:hlbox_bg]
		else
			gc.set_foreground @color[:box_bg]
		end
		w.draw_rectangle(gc, true, (b.x-@curcontext.view_x)*@zoom, (b.y-@curcontext.view_y)*@zoom, b.w*@zoom, b.h*@zoom)

		return if @zoom < 0.99 or @zoom > 1.1
		# TODO dynamic font size ?

		# current text position
		x = (b.x - @curcontext.view_x + 1)*@zoom
		y = (b.y - @curcontext.view_y + 1)*@zoom
		w_w = (b.x - @curcontext.view_x)*@zoom + b.w - @font_width
		w_h = (b.y - @curcontext.view_y)*@zoom + b.h - @font_height

		if @caret_box == b
			gc.set_foreground @color[:cursorline_bg]
			w.draw_rectangle(gc, true, x-1, y+@caret_y*@font_height, b.w*@zoom-2, @font_height)
		end

		# renders a string at current cursor position with a color
		# must not include newline
		render = lambda { |str, color|
			# function ends when we write under the bottom of the listing
			next if y >= w_h or x >= w_w
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
		# newline: current line is fully rendered, update line_address/line_text etc
		nl = lambda {
			x = (b.x - @curcontext.view_x + 1)*@zoom
			y += @font_height
		}

		b[:addresses].each { |addr|
			curaddr = addr
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
				end
				render[di.instruction.to_s.ljust(di.comment ? 24 : 0), :instruction]
				render[' ; ' + di.comment.join(' ')[0, 64], :comment] if di.comment
				nl[]
			else
				# TODO real data display (dwords, xrefs, strings..)
				if label = @dasm.prog_binding.index(curaddr) and @dasm.xrefs[curaddr]
					render[Expression[curaddr].to_s + '    ', :black]
					render[label + ' ', :label]
				else
					if label
						render[label+':', :label]
						nl[]
					end
					render[Expression[curaddr].to_s + '    ', :black]
				end
				s = @dasm.get_section_at(curaddr)
				render['db '+((s and s[0].data.length > s[0].ptr) ? Expression[s[0].read(1)[0]].to_s : '?'), :instruction]
				nl[]
			end
		}

		if b == @caret_box
			gc.set_foreground @color[:caret]
			cx = (b.x - @curcontext.view_x + 1)*@zoom + @caret_x*@font_width
			cy = (b.y - @curcontext.view_y + 1)*@zoom + @caret_y*@font_height
			w.draw_line(gc, cx, cy, cx, cy+@font_height-1)
		end
	end

	#
	# rebuild the code flow graph from @curcontext.roots
	# recalc the boxes w/h
	#
	def gui_update(ctx=@curcontext)
		boxcnt = ctx.box.length
		arrcnt = ctx.box.inject(0) { |s, b| s + b.to.length + b.from.length }
		ctx.clear

		# graph : block -> following blocks in same function
		block_rel = {}

		todo = ctx.root_addrs.dup
		done = [:default, Expression::Unknown]
		while a = todo.shift
			a = @dasm.normalize a
			next if done.include? a
			done << a
			next if not di = @dasm.decoded[a] or not di.kind_of? DecodedInstruction
			block_rel[a] = []
			di.block.each_to_samefunc(@dasm) { |t|
				t = @dasm.normalize t
				next if not @dasm.decoded[t].kind_of? DecodedInstruction
				todo << t
				block_rel[a] << t
			}
			block_rel[a].uniq!
		end

		# populate boxes
		addr2box = {}
		todo = ctx.root_addrs.dup
		done = []
		while a = todo.shift
			next if done.include? a
			done << a
			if not ctx.keep_split.to_a.include?(a) and from = block_rel.keys.find_all { |ba| block_rel[ba].include? a } and
					from.length == 1 and block_rel[from.first].length == 1 and
					addr2box[from.first] and lst = @dasm.decoded[from.first].block.list.last and
					lst.next_addr == a and (not lst.opcode.props[:saveip] or lst.block.to_subfuncret)
				box = addr2box[from.first]
			else
				box = ctx.new_box a, :addresses => [], :line_text => {}, :line_address => {}
			end
			@dasm.decoded[a].block.list.each { |di_|
				box[:addresses] << di_.address
				addr2box[di_.address] = box
			}
			todo.concat block_rel[a]
		end

		# link boxes
		ctx.box.each { |b|
			next if not @dasm.decoded[b[:addresses].last]
			a = @dasm.decoded[b[:addresses].last].block.address
			next if not block_rel[a]
			block_rel[a].each { |t|
				ctx.link_boxes(b.id, t)
			}
		}

		# calc box dimensions
		ctx.box.each { |b|
			fullstr = ''
			curaddr = nil
			line = 0
			render = lambda { |str| fullstr << str }
			nl = lambda {
				b[:line_address][line] = curaddr
				b[:line_text][line] = fullstr
				fullstr = ''
				line += 1
			}
			b[:addresses].each { |addr|
				curaddr = addr
				if di = @dasm.decoded[curaddr] and di.kind_of? DecodedInstruction
					if di.block.list.first == di
						b_header = '' ; @dasm.dump_block_header(di.block) { |l| b_header << l ; b_header << ?\n if b_header[-1] != ?\n }
						b_header.each { |l| render[l.chomp] ; nl[] }
					end
					render[di.instruction.to_s.ljust(di.comment ? 24 : 0)]
					render[' ; ' + di.comment.join(' ')[0, 64]] if di.comment
					nl[]
				end
			}
			b.w = b[:line_text].values.map { |str| str.length }.max.to_i * @font_width + 2
			b.w += 1 if b.w % 2 == 0	# ensure boxes have odd width -> vertical arrows are straight
			b.h = line * @font_height + 2
		}

		ctx.auto_arrange_boxes

		return if ctx != @curcontext

		if boxcnt != ctx.box.length or arrcnt != ctx.box.inject(0) { |s, b| s + b.to.length + b.from.length }
			zoom_all
		end

		redraw
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
	# TODO arrows => change caret_box
	# TODO non-navigation commands are global, get it out of the widget
	def keypress(ev)
		return @parent_widget.keypress(ev) if ev.state & Gdk::Window::CONTROL_MASK != 0
		case ev.keyval
		when GDK_Left
			if @caret_box
				if @caret_x > 0
					@caret_x -= 1
					update_caret
				elsif b = @curcontext.box.sort_by { |b_| -b_.x }.find { |b_| b_.x < @caret_box.x and
						b_.y < @caret_box.y+@caret_y*@font_height and
						b_.y+b_.h > @caret_box.y+(@caret_y+1)*@font_height }
					@caret_x = (b.w/@font_width).to_i
					@caret_y += ((@caret_box.y-b.y)/@font_height).to_i
					@caret_box = b
					update_caret
					redraw
				else
					@curcontext.view_x -= 20/@zoom
					redraw
				end
			else
				@curcontext.view_x -= 20/@zoom
				redraw
			end
		when GDK_Up
			if @caret_box
				if @caret_y > 0
					@caret_y -= 1
					update_caret
				elsif b = @curcontext.box.sort_by { |b_| -b_.y }.find { |b_| b_.y < @caret_box.y and
						b_.x < @caret_box.x+@caret_x*@font_width and
						b_.x+b_.w > @caret_box.x+(@caret_x+1)*@font_width }
					@caret_x += ((@caret_box.x-b.x)/@font_width).to_i
					@caret_y = b[:line_text].keys.max
					@caret_box = b
					update_caret
					redraw
				else
					@curcontext.view_y -= 20/@zoom
					redraw
				end
			else
				@curcontext.view_y -= 20/@zoom
				redraw
			end
		when GDK_Right
			if @caret_box
				if @caret_x <= @caret_box[:line_text].values.map { |s| s.length }.max
					@caret_x += 1
					update_caret
				elsif b = @curcontext.box.sort_by { |b_| b_.x }.find { |b_| b_.x > @caret_box.x and
						b_.y < @caret_box.y+@caret_y*@font_height and
						b_.y+b_.h > @caret_box.y+(@caret_y+1)*@font_height }
					@caret_x = 0
					@caret_y += ((@caret_box.y-b.y)/@font_height).to_i
					@caret_box = b
					update_caret
					redraw
				else
					@curcontext.view_x += 20/@zoom
					redraw
				end
			else
				@curcontext.view_x += 20/@zoom
				redraw
			end
		when GDK_Down
			if @caret_box
				if @caret_y < @caret_box[:line_text].length-1
					@caret_y += 1
					update_caret
				elsif b = @curcontext.box.sort_by { |b_| b_.y }.find { |b_| b_.y > @caret_box.y and
						b_.x < @caret_box.x+@caret_x*@font_width and
						b_.x+b_.w > @caret_box.x+(@caret_x+1)*@font_width }
					@caret_x += ((@caret_box.x-b.x)/@font_width).to_i
					@caret_y = 0
					@caret_box = b
					update_caret
					redraw
				else
					@curcontext.view_y += 20/@zoom
					redraw
				end
			else
				@curcontext.view_y += 20/@zoom
				redraw
			end
		when GDK_Page_Up
			if @caret_box
				@caret_y = 0
				update_caret
			else
				@curcontext.view_y -= @height/4/@zoom
				redraw
			end
		when GDK_Page_Down
			if @caret_box
				@caret_y = @caret_box[:line_text].length-1
				update_caret
			else
				@curcontext.view_y += @height/4/@zoom
				redraw
			end
		when GDK_Home
			if @caret_box
				@caret_x = 0
				update_caret
			else
				@curcontext.view_x = @curcontext.box.map { |b_| b_.x }.min-10
				@curcontext.view_y = @curcontext.box.map { |b_| b_.y }.min-10
				redraw
			end
		when GDK_End
			if @caret_box
				@caret_x = @caret_box[:line_text][@caret_y].length
				update_caret
			else
				@curcontext.view_x = [@curcontext.box.map { |b_| b_.x+b_.w }.max-@width/@zoom+10, @curcontext.box.map { |b_| b_.x }.min-10].max
				@curcontext.view_y = [@curcontext.box.map { |b_| b_.y+b_.h }.max-@height/@zoom+10, @curcontext.box.map { |b_| b_.y }.min-10].max
				redraw
			end

		when GDK_Delete
			@selected_boxes.each { |b_|
				@curcontext.box.delete b_
				b_.from.each { |bb| bb.to.delete b_ }
				b_.to.each { |bb| bb.from.delete b_ }
			}
			redraw

		when GDK_a
			puts 'autoarrange'
			@curcontext.auto_arrange_boxes
			redraw
			puts 'autoarrange done'
		when GDK_u
			puts 'update'
			gui_update
			redraw
			puts 'update done'
		when GDK_1
			@curcontext.view_x += (@width/2 / @zoom - @width/2)
			@curcontext.view_y += (@height/2 / @zoom - @height/2)
			@zoom = 1.0
			redraw
		when GDK_Insert		# split curbox at @caret_y
			if @caret_box and a = @caret_box[:line_address][@caret_y] and @dasm.decoded[a]
				@dasm.split_block(@dasm.decoded[a].block, a)
				@curcontext.keep_split ||= []
				@curcontext.keep_split |= [a]
				gui_update
				focus_addr a
			end

		else
			return @parent_widget.keypress(ev)
		end
		true
	end

	# find a suitable array of graph roots, walking up from a block (function start/entrypoint)
	def dasm_find_roots(addr)
		todo = [addr]
		done = []
		roots = []
		while a = todo.shift
			a = @dasm.normalize(a)
			next if done.include? a
			next if not b = @dasm.decoded[a] or not b.kind_of? DecodedInstruction or not b = b.block
			done << a
			newf = []
			b.each_from_samefunc(@dasm) { |f| newf << f }
			if newf.empty?
				roots << b.address
			else
				todo.concat newf
			end
		end

		roots
	end

	def set_cursor_pos(p)
		addr, x = p
		focus_addr(addr)
		@caret_x = x
		update_caret
	end

	def get_cursor_pos
		[current_address, @caret_x]
	end

	# queue redraw of the whole GUI visible area
	def redraw
		return if not @drawarea.window
		@drawarea.window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false
	end

	# change the color association
	# arg is a hash function symbol => color symbol
	# color must be allocated
	# check #initialize/sig('realize') for initial function/color list
	def set_color_association(hash)
		hash.each { |k, v| @color[k] = @color[v] }
		@drawarea.modify_bg Gtk::STATE_NORMAL, @color[:bg]
		gui_update
	end

	# change the font of the listing
	# arg is a Gtk Fontdescription string (eg 'courier 10')
	def set_font(descr)
		@layout.font_description = Pango::FontDescription.new(descr)
		@layout.text = 'x'
		@font_width, @font_height = @layout.pixel_size
		redraw
	end

	# focus on addr
	# addr may be a dasm label, dasm address, dasm address in string form (eg "0DEADBEEFh")
	# addr must point to a decodedinstruction
	# if the addr is not found in curcontext, the code flow is walked up until a function
	# start or an entrypoint is found, then the graph is created from there
	# will call gui_update then
	def focus_addr(addr, can_update_context=true)
		if not @dasm.decoded[addr].kind_of? DecodedInstruction
			return
		end

		# move window / change curcontext
		if b = @curcontext.box.find { |b_| b_[:line_address].index(addr) }
			@caret_box, @caret_x, @caret_y = b, 0, b[:line_address].index(addr)
			@curcontext.view_x += (@width/2 / @zoom - @width/2)
			@curcontext.view_y += (@height/2 / @zoom - @height/2)
			@zoom = 1.0

			focus_xy(b.x, b.y + @caret_y*@font_height)
			update_caret
		elsif can_update_context
			@curcontext = Graph.new 'testic'
			@curcontext.root_addrs = dasm_find_roots(addr)
			gui_update
			return if not @curcontext.box.first
			# find an address that can be shown if addr is not
			if not @curcontext.box.find { |b_| b_[:line_address].index(addr) }
				addr = @curcontext.box.first[:line_address].values.first
			end
			return focus_addr(addr, false)
		else
			return
		end
		true
	end

	def focus_xy(x, y)
		if not @curcontext.view_x or @curcontext.view_x*@zoom + @width*3/4 < x or @curcontext.view_x*@zoom > x
			@curcontext.view_x = (x - @width/5)/@zoom
			redraw
		end
		if not @curcontext.view_y or @curcontext.view_y*@zoom + @height*3/4 < y or @curcontext.view_y*@zoom > y
			@curcontext.view_y = (y - @height/5)/@zoom
			redraw
		end
	end

	# hint that the caret moved
	# redraw, change the hilighted word
	def update_caret
		return if not @caret_box or not @caret_x or not l = @caret_box[:line_text][@caret_y]
		word = l[0...@caret_x].to_s[/\w*$/] << l[@caret_x..-1].to_s[/^\w*/]
		word = nil if word == ''
		@hl_word = word
		redraw
	end

	def current_address
		@caret_box[:line_address][@caret_y] if @caret_box
	end
end
end
end
