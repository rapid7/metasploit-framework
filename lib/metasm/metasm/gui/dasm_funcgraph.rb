#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/gui/dasm_graph'

module Metasm
module Gui
class FuncGraphViewWidget < GraphViewWidget
	# :full / :from / :to / :both
	# :from = graph of functions called by addr
	# :to = graph of functions calling addr
	attr_accessor :graph_mode
	def initialize(*a)
		super(*a)
		@graph_mode = :full
	end

	def build_ctx(ctx)
		addr = @curcontext.root_addrs[0]
		case @graph_mode
		when :full
			g = @dasm.function_graph
		when :from
			g = @dasm.function_graph_from(addr)
		when :to
			g = @dasm.function_graph_to(addr)
		when :both
			# merge from+to
			g = @dasm.function_graph_to(addr)
			@dasm.function_graph_from(addr).each { |k, v|
				g[k] ||= v
				g[k] |= v
			}
		end
		g = {addr => []} if not g or g.empty?

		# create boxes
		(g.keys + g.values).flatten.uniq.each { |a|
			# box text
			txt = @dasm.get_label_at(a)
			txt ||= Expression[a].to_s
			b = ctx.new_box a, :addresses => [a], :line_text_col => [], :line_address => [a]
			b[:line_text_col] << [[txt, :label]]
			b.w = txt.length * @font_width + 2
			b.h = @font_height
		}

		# link boxes
		g.each { |f, tl| tl.each { |t| ctx.link_boxes(f, t) } }

	end

	def doubleclick(x, y)
		if find_box_xy(x, y) and @hl_word and @zoom >= 0.90 and @zoom <= 1.1
			@mousemove_origin = nil
			@parent_widget.focus_addr(@hl_word, :graph)
		else
			super(x, y)
		end
	end

	def get_cursor_pos
		[@curcontext.root_addrs[0], @graph_mode]
	end

	def set_cursor_pos(p)
		addr, m = p
		focus_addr(addr, m)
		@caret_x = 0
		update_caret
	end

	def focus_addr(addr, mode=@graph_mode)
		if mode == false
			# simply center the view on addr in the current graph
			raise 'fu' if not b = @curcontext.box.find { |b_| b_[:line_address][0] == addr }
			@caret_box, @caret_x, @caret_y = b, 0, 0
			@curcontext.view_x += (width/2 / @zoom - width/2)
			@curcontext.view_y += (height/2 / @zoom - height/2)
			@zoom = 1.0

			focus_xy(b.x, b.y)
			update_caret
			return
		end

		return if not addr = @dasm.normalize(addr)
		if not @dasm.function[addr]
			return if not addr = @dasm.find_function_start(addr)
		end
		return true if @curcontext.root_addrs == [addr] and @graph_mode == mode
		@graph_mode = mode
		@curcontext = Graph.new('fu')
		@curcontext.root_addrs = [addr]
		@want_focus_addr = addr
		gui_update
		true
	end
end
end
end
