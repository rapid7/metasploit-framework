#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

module Metasm
module Gui
class Graph
  # one box, has a text, an id, and a list of other boxes to/from
  class Box
    attr_accessor :id, :x, :y, :w, :h
    attr_accessor :to, :from # other boxes linked (arrays)
    attr_accessor :content
    attr_accessor :direct_to
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
    @view_x = @view_y = -0xfff_ffff
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
  def auto_arrange_init(list=@box)
    # groups is an array of box groups
    # all groups are centered on the origin
    @groups = list.map { |b|
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
    @groups.each { |g|
      g.to   = g.content.first.to.map   { |t| next if not t = list.index(t) ; @groups[t] }.compact - [g]
      g.from = g.content.first.from.map { |f| next if not f = list.index(f) ; @groups[f] }.compact - [g]
    }

    # walk from a box, fork at each multiple to, chop links to a previous box (loops etc)
    @madetree = false
  end

  # gives a text representation of the current graph state
  def dump_layout(groups=@groups)
    groups.map { |g| "#{groups.index(g)} -> #{g.to.map { |t| groups.index(t) }.sort.inspect}" }
  end

  def auto_arrange_step
    # TODO fix
    #  0->[1, 2] 1->[3] 2->[3, 4] 3->[] 4->[1]
    #  push 0 jz l3  push 1 jz l4  push 2  l3: push 3  l4: hlt
    # and more generally all non-looping graphs where this algo creates backward links

    groups = @groups
    return if groups.length <= 1

    maketree = lambda { |roots|
      next if @madetree
      @madetree = true

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

      roots.each { |g| trim[g, g.from] unless g.from.empty? }
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
      groups = @groups = groups - ary
      groups.insert(idx, bg)
      bg
    }

    # move all boxes within group of dx, dy
    move_group = lambda { |g, dx, dy|
      g.content.each { |b| b.x += dx ; b.y += dy }
      g.x += dx ; g.y += dy
    }

    align_hz = lambda { |ary|
      # if we have one of the block much bigger than the others, put it on the far right
      big = ary.sort_by { |g| g.h }.last
      if (ary-[big]).all? { |g| g.h < big.h/3 }
        ary -= [big]
      else
        big = nil
      end
      nx = ary.map { |g| g.w }.inject(0) { |a, b| a+b } / -2
      nx *= 2 if big and ary.length == 1	# just put the parent on the separation of the 2 child
      ary.each { |g|
        move_group[g, nx-g.x, 0]
        nx += g.w
      }
      move_group[big, nx-big.x, 0] if big
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
      if groups.all? { |g1| g1.from.empty? and g1.to.empty? }
        # disjoint subgraphs
        align_hz[groups]
        merge_groups[groups]
        next true
      end

      groups.find { |g1|
        ary = g1.from.map { |gg| gg.to }.flatten.uniq.find_all { |gg|
          gg != g1 and
          (gg.from - g1.from).empty? and (g1.from - gg.from).empty? and
          (strict ? ((gg.to - g1.to).empty? and (g1.to - gg.to).empty?) : (g1.to & gg.to).first)
        }
        ary = g1.to.map { |gg| gg.from }.flatten.uniq.find_all { |gg|
          gg != g1 and
          (gg.to - g1.to).empty? and (g1.to - gg.to).empty? and
          (strict ? ((gg.from - g1.from).empty? and (g1.from - gg.from).empty?) : (g1.from & gg.from).first)
        } if ary.empty?
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

    group_inv_if = {}

    # scan groups for a if/then pattern (1 -> 2 -> 3 & 1 -> 3)
    group_ifthen = lambda { |strict|
      groups.reverse.find { |g|
        next if not g2 = g.to.find { |g2_| (g2_.to.length == 1 and g.to.include?(g2_.to.first)) or
          (not strict and g2_.to.empty?)  }
        next if strict and g2.from != [g] or g.to.length != 2
        g2.h += 16 ; g2.y -= 8
        align_vt[[g, g2]]
        dx = -g2.x+8
        dx -= g2.w+16 if group_inv_if[g]
        move_group[g2, dx, 0]
        merge_groups[[g, g2]]
        true
      }
    }

    # if (a || b) c;
    # the 'else' case handles '&& else', and && is two if/then nested
    group_or = lambda { |strict|
      groups.find { |g|
        next if g.to.length != 2
        g2 = g.to[0]
        g2 = g.to[1] if not g2.to.include? g.to[1]
        thn = (g.to & g2.to).first
        next if g2.to.length != 2 or not thn or thn.to.length != 1
        els = (g2.to - [thn]).first
        if thn.to == [els]
          els = nil
        elsif els.to != thn.to
          next if strict
          align_vt[[g, g2]]
          merge_groups[[g, g2]]
          break true
        else
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
      ary = nil
      if groups.find { |g| ary = g.from.find_all { |gg| gg.to == [g] } and ary.length > 1 } or
         groups.find { |g| ary = g.to.find_all { |gg| gg.from == [g] } and ary.length > 1 }
        align_hz[ary]
        merge_groups[ary]
        true
      end
    }


    # unknown pattern, group as we can..
    group_other = lambda {
puts 'graph arrange: unknown configuration', dump_layout
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

    # check constructs with multiple blocks with to to end block (a la break;)
    ign_break = lambda {
      can_reach = lambda { |b1, b2, term|
        next if b1 == term
        done = [term]
        todo = b1.to.dup
        while t = todo.pop
          next if done.include? t
          done << t
          break true if t == b2
          todo.concat t.to
        end
      }
      can_reach_unidir = lambda { |b1, b2, term| can_reach[b1, b2, term] and not can_reach[b2, b1, term] }
      groups.find { |g|
        f2 = nil
        if (g.from.length > 2 and f3 = g.from.find { |f| f.to == [g] } and f1 = g.from.find { |f|
          f2 = g.from.find { |ff| can_reach_unidir[ff, f3, g] and can_reach_unidir[f, ff, g] }}) or
           (g.to.length > 2 and f3 = g.to.find { |f| f.from == [g] } and f1 = g.to.find { |f|
          f2 = g.to.find { |ff| can_reach_unidir[f3, ff, g] and can_reach_unidir[ff, f, g] }})
          group_inv_if[f1] = true
          if f3.to == [g]
            g.from.delete f2
            f2.to.delete g
          else
            g.to.delete f2
            f2.from.delete g
          end
          true
        end
      }
    }

    # walk graph from roots, cut backward links
    trim_graph = lambda {
      next true if ign_break[]
      g1 = groups.find_all { |g| g.from.empty? }
      g1 << groups.first if g1.empty?
      cntpre = groups.inject(0) { |cntpre_, g| cntpre_ + g.to.length }
      g1.each { |g| maketree[[g]] }
      cntpost = groups.inject(0) { |cntpre_, g| cntpre_ + g.to.length }
      true if cntpre != cntpost
    }

    # known, clean patterns
    group_clean = lambda {
      group_columns[] or group_lines[true] or group_ifthen[true] or group_loop[] or group_or[true]
    }
    # approximations
    group_unclean = lambda {
      group_lines[false] or group_or[false] or group_halflines[] or group_ifthen[false] or group_other[]
    }

    group_clean[] or trim_graph[] or group_unclean[]
  end

  # the boxes have been almost put in place, here we soften a little the result & arrange some qwirks
  def auto_arrange_post
    # entrypoint should be above other boxes, same for exitpoints
    @box.each { |b|
      if b.from == []
        chld = b.to
        chld = @box - [b] if not @box.find { |bb| bb != b and bb.from == [] }
        chld.each { |t| b.y = t.y - b.h - 16 if t.y < b.y+b.h }
      end
      if b.to == []
        chld = b.from
        chld = @box - [b] if not @box.find { |bb| bb != b and bb.to == [] }
        chld.each { |f| b.y = f.y + f.h + 16 if f.y+f.h > b.y }
      end
    }

    boxxy = @box.sort_by { |bb| bb.y }
    # fill gaps that we created
    @box.each { |b|
      bottom = b.y+b.h
      next if not follower = boxxy.find { |bb| bb.y+bb.h > bottom }

      # preserve line[] constructs margins
      gap = follower.y-16*follower.from.length - (bottom+16*b.to.length)
      next if gap <= 0

      @box.each { |bb|
        if bb.y+bb.h <= bottom
          bb.y += gap/2
        else
          bb.y -= gap/2
        end
      }
      boxxy = @box.sort_by { |bb| bb.y }
    }

    @box[0,0].each { |b|
      # TODO elastic positionning (ignore up arrows ?) & collision detection (box/box + box/arrow)
      f = b.from[0]
      t = b.to[0]
      if b.to.length == 1 and b.from.length == 1 and b.y+b.h<t.y and b.y>f.y+f.h
        wx = (t.x+t.w/2 + f.x+f.w/2)/2 - b.w/2
        wy = (t.y + f.y+f.h)/2 - b.h/2
        b.x += (wx-b.x)/5
        b.y += (wy-b.y)/5
      end
    }

  end

  def auto_arrange_boxes
    auto_arrange_init
    nil while @groups.length > 1 and auto_arrange_step
    @groups = []
    auto_arrange_post
  end
end





class GraphViewWidget < DrawableWidget
  attr_accessor :dasm, :caret_box, :curcontext, :zoom, :margin
  # bool, specifies if we should display addresses before instrs
  attr_accessor :show_addresses

  def initialize_widget(dasm, parent_widget)
    @dasm = dasm
    @parent_widget = parent_widget

    @show_addresses = false

    @caret_box = nil
    @selected_boxes = []
    @shown_boxes = []
    @mousemove_origin = @mousemove_origin_ctrl = nil
    @curcontext = Graph.new(nil)
    @margin = 8
    @zoom = 1.0
    @default_color_association = { :background => :paleblue, :hlbox_bg => :palegrey, :box_bg => :white,
        :text => :black, :arrow_hl => :red, :comment => :darkblue, :address => :darkblue,
        :instruction => :black, :label => :darkgreen, :caret => :black, :hl_word => :palered,
        :cursorline_bg => :paleyellow, :arrow_cond => :darkgreen, :arrow_uncond => :darkblue,
               :arrow_direct => :darkred }
    # @othergraphs = ?	(to keep user-specified formatting)
  end

  def resized(w, h)
    redraw
  end

  def find_box_xy(x, y)
    x = @curcontext.view_x+x/@zoom
    y = @curcontext.view_y+y/@zoom
    @shown_boxes.to_a.reverse.find { |b| b.x <= x and b.x+b.w > x and b.y <= y-1 and b.y+b.h > y+1 }
  end

  def mouse_wheel_ctrl(dir, x, y)
    case dir
    when :up
      if @zoom < 100
        oldzoom = @zoom
        @zoom *= 1.1
        @zoom = 1.0 if (@zoom-1.0).abs < 0.05
        @curcontext.view_x += (x / oldzoom - x / @zoom)
        @curcontext.view_y += (y / oldzoom - y / @zoom)
      end
    when :down
      if @zoom > 1.0/100
        oldzoom = @zoom
        @zoom /= 1.1
        @zoom = 1.0 if (@zoom-1.0).abs < 0.05
        @curcontext.view_x += (x / oldzoom - x / @zoom)
        @curcontext.view_y += (y / oldzoom - y / @zoom)
      end
    end
    redraw
  end

  def mouse_wheel(dir, x, y)
    case dir
    when :up; @curcontext.view_y -= height/4 / @zoom
    when :down; @curcontext.view_y += height/4 / @zoom
    end
    redraw
  end

  def mousemove(x, y)
    return if not @mousemove_origin

    dx = (x - @mousemove_origin[0])/@zoom
    dy = (y - @mousemove_origin[1])/@zoom
    @mousemove_origin = [x, y]
    if @selected_boxes.empty?
      @curcontext.view_x -= dx ; @curcontext.view_y -= dy
    else
      @selected_boxes.each { |b| b.x += dx ; b.y += dy }
    end
    redraw
  end

  def mouserelease(x, y)
    mousemove(x, y)
    @mousemove_origin = nil

    if @mousemove_origin_ctrl
      x1 = @curcontext.view_x + @mousemove_origin_ctrl[0]/@zoom
      x2 = x1 + (x - @mousemove_origin_ctrl[0])/@zoom
      x1, x2 = x2, x1 if x1 > x2
      y1 = @curcontext.view_y + @mousemove_origin_ctrl[1]/@zoom
      y2 = y1 + (y - @mousemove_origin_ctrl[1])/@zoom
      y1, y2 = y2, y1 if y1 > y2
      @selected_boxes |= @curcontext.box.find_all { |b| b.x >= x1 and b.x + b.w <= x2 and b.y >= y1 and b.y + b.h <= y2 }
      redraw
      @mousemove_origin_ctrl = nil
    end
  end

  def click_ctrl(x, y)
    if b = find_box_xy(x, y)
      if @selected_boxes.include? b
        @selected_boxes.delete b
      else
        @selected_boxes << b
      end
      redraw
    else
      @mousemove_origin_ctrl = [x, y]
    end
  end

  def click(x, y)
    @mousemove_origin = [x, y]
    if b = find_box_xy(x, y)
      @selected_boxes = [b] if not @selected_boxes.include? b
      @caret_box = b
      @caret_x = (@curcontext.view_x+x/@zoom-b.x-1).to_i / @font_width
      @caret_y = (@curcontext.view_y+y/@zoom-b.y-1).to_i / @font_height
      update_caret
    else
      @selected_boxes = []
      @caret_box = nil
    end
    redraw
  end

  # if the target is a call to a subfunction, open a new window with the graph of this function (popup)
  def rightclick(x, y)
    if b = find_box_xy(x, y) and @zoom >= 0.90 and @zoom <= 1.1
      click(x, y)
      @mousemove_origin = nil
      @parent_widget.clone_window(@hl_word, :graph)
    end
  end

  def doubleclick(x, y)
    if b = find_box_xy(x, y)
      @mousemove_origin = nil
      if @hl_word and @zoom >= 0.90 and @zoom <= 1.1
        @parent_widget.focus_addr(@hl_word)
      else
        @parent_widget.focus_addr b[:addresses].first
      end
    elsif doubleclick_check_arrow(x, y)
    elsif @zoom == 1.0
      zoom_all
    else
      @curcontext.view_x += (x/@zoom - x)
      @curcontext.view_y += (y/@zoom - y)
      @zoom = 1.0
    end
    redraw
  end

  # check if the user clicked on the beginning/end of an arrow, if so focus on the other end
  def doubleclick_check_arrow(x, y)
    return if @margin*@zoom < 2
    x = @curcontext.view_x+x/@zoom
    y = @curcontext.view_y+y/@zoom
    sx = nil
    if bt = @shown_boxes.to_a.reverse.find { |b|
      y >= b.y+b.h-1 and y <= b.y+b.h-1+@margin+2 and
      sx = b.x+b.w/2 - b.to.length/2 * @margin/2 and
             x >= sx-@margin/2 and x <= sx+b.to.length*@margin/2	# should be margin/4, but add a little comfort margin
    }
      idx = (x-sx+@margin/4).to_i / (@margin/2)
      idx = 0 if idx < 0
      idx = bt.to.length-1 if idx >= bt.to.length
      if bt.to[idx]
        if @parent_widget
      @parent_widget.focus_addr bt.to[idx][:line_address][0]
        else
          focus_xy(bt.to[idx].x, bt.to[idx].y)
        end
      end
      true
    elsif bf = @shown_boxes.to_a.reverse.find { |b|
      y >= b.y-@margin-2 and y <= b.y and
      sx = b.x+b.w/2 - b.from.length/2 * @margin/2 and
             x >= sx-@margin/2 and x <= sx+b.from.length*@margin/2
    }
      idx = (x-sx+@margin/4).to_i / (@margin/2)
      idx = 0 if idx < 0
      idx = bf.from.length-1 if idx >= bf.from.length
      if bf.from[idx]
        if @parent_widget
      @parent_widget.focus_addr bf.from[idx][:line_address][-1]
        else
          focus_xy(bt.from[idx].x, bt.from[idx].y)
        end
      end
      true
    end
  end

  # update the zoom & view_xy to show the whole graph in the window
  def zoom_all
    minx = @curcontext.box.map { |b| b.x }.min.to_i - 10
    miny = @curcontext.box.map { |b| b.y }.min.to_i - 10
    maxx = @curcontext.box.map { |b| b.x + b.w }.max.to_i + 10
    maxy = @curcontext.box.map { |b| b.y + b.h }.max.to_i + 10
    @zoom = [width.to_f/(maxx-minx), height.to_f/(maxy-miny)].min
    @zoom = 1.0 if @zoom > 1.0 or (@zoom-1.0).abs < 0.1
    @curcontext.view_x = minx + (maxx-minx-width/@zoom)/2
    @curcontext.view_y = miny + (maxy-miny-height/@zoom)/2
    redraw
  end

  def paint
    update_graph if @want_update_graph
    if @want_focus_addr and @curcontext.box.find { |b_| b_[:line_address].index(@want_focus_addr) }
      focus_addr(@want_focus_addr, false)
      @want_focus_addr = nil
      #zoom_all
    end

    @curcontext.box.each { |b|
      # reorder arrows so that endings do not overlap
      b.to = b.to.sort_by { |bt| bt.x+bt.w/2 }
      b.from = b.from.sort_by { |bt| bt.x+bt.w/2 }
    }
    # arrows drawn first to stay under the boxes
    # XXX precalc ?
    @curcontext.box.each { |b|
      b.to.each { |bt| paint_arrow(b, bt) }
    }

    @shown_boxes = []
    w_w, w_h = width, height
    @curcontext.box.each { |b|
      next if b.x >= @curcontext.view_x+w_w/@zoom or b.y >= @curcontext.view_y+w_h/@zoom or b.x+b.w <= @curcontext.view_x or b.y+b.h <= @curcontext.view_y
      @shown_boxes << b
      paint_box(b)
    }
  end

  def set_color_arrow(b1, b2)
    if b1 == @caret_box or b2 == @caret_box
      draw_color :arrow_hl
    elsif b1.to.length == 1
      draw_color :arrow_uncond
    elsif b1.direct_to == b2.id
      draw_color :arrow_direct
    else
      draw_color :arrow_cond
    end
  end

  def paint_arrow(b1, b2)
    x1, y1 = b1.x+b1.w/2-@curcontext.view_x, b1.y+b1.h-@curcontext.view_y
    x2, y2 = b2.x+b2.w/2-@curcontext.view_x, b2.y-1-@curcontext.view_y
    x1o, x2o = x1, x2
    margin = @margin
    x1 += (-(b1.to.length-1)/2 + b1.to.index(b2)) * margin/2
    x2 += (-(b2.from.length-1)/2 + b2.from.index(b1)) * margin/2
    return if (y1+margin < 0 and y2 < 0) or (y1 > height/@zoom and y2-margin > height/@zoom)	# just clip on y
    margin, x1, y1, x2, y2, b1w, b2w, x1o, x2o = [margin, x1, y1, x2, y2, b1.w, b2.w, x1o, x2o].map { |v| v*@zoom }


    # XXX gtk wraps coords around 0x8000
    if x1.abs > 0x7000 ; y1 /= x1.abs/0x7000 ; x1 /= x1.abs/0x7000 ; end
    if y1.abs > 0x7000 ; x1 /= y1.abs/0x7000 ; y1 /= y1.abs/0x7000 ; end
    if x2.abs > 0x7000 ; y2 /= x2.abs/0x7000 ; x2 /= x2.abs/0x7000 ; end
    if y2.abs > 0x7000 ; x2 /= y2.abs/0x7000 ; y2 /= y2.abs/0x7000 ; end

    # straighten vertical arrows if possible
    if y2 > y1 and (x1-x2).abs <= margin
      if b1.to.length == 1
        x1 = x2
      elsif b2.from.length == 1
        x2 = x1
      end
    end

    set_color_arrow(b1, b2)
    if margin > 1
      # draw arrow tip
      draw_line(x1, y1, x1, y1+margin)
      draw_line(x2, y2-margin+1, x2, y2)
      draw_line(x2-margin/2, y2-margin/2, x2, y2)
      draw_line(x2+margin/2, y2-margin/2, x2, y2)
      y1 += margin
      y2 -= margin-1
    end
    if y2+margin >= y1-margin-1
      # straight vertical down arrow
      draw_line(x1, y1, x2, y2) if x1 != y1 or x2 != y2

    # else arrow up, need to sneak around boxes
    elsif x1o-b1w/2-margin >= x2o+b2w/2+margin	# z
      draw_line(x1, y1, x1o-b1w/2-margin, y1)
      draw_line(x1o-b1w/2-margin, y1, x2o+b2w/2+margin, y2)
      draw_line(x2o+b2w/2+margin, y2, x2, y2)
      draw_line(x1, y1+1, x1o-b1w/2-margin, y1+1) # double
      draw_line(x1o-b1w/2-margin+1, y1, x2o+b2w/2+margin+1, y2)
      draw_line(x2o+b2w/2+margin, y2+1, x2, y2+1)
    elsif x1+b1w/2+margin <= x2-b2w/2-margin	# invert z
      draw_line(x1, y1, x1o+b1w/2+margin, y1)
      draw_line(x1o+b1w/2+margin, y1, x2o-b2w/2-margin, y2)
      draw_line(x2o-b2w/2-margin, y2, x2, y2)
      draw_line(x1, y1+1, x1+b1w/2+margin, y1+1) # double
      draw_line(x1o+b1w/2+margin+1, y1, x2o-b2w/2-margin+1, y2)
      draw_line(x2o-b2w/2-margin, y2+1, x2, y2+1)
    else						# turn around
      x = (x1 <= x2 ? [x1o-b1w/2-margin, x2o-b2w/2-margin].min : [x1o+b1w/2+margin, x2o+b2w/2+margin].max)
      draw_line(x1, y1, x, y1)
      draw_line(x, y1, x, y2)
      draw_line(x, y2, x2, y2)
      draw_line(x1, y1+1, x, y1+1) # double
      draw_line(x+1, y1, x+1, y2)
      draw_line(x, y2+1, x2, y2+1)
    end
  end

  def set_color_boxshadow(b)
    draw_color :black
  end

  def set_color_box(b)
    if @selected_boxes.include? b
      draw_color :hlbox_bg
    else
      draw_color :box_bg
    end
  end

  def paint_box(b)
    set_color_boxshadow(b)
    draw_rectangle((b.x-@curcontext.view_x+3)*@zoom, (b.y-@curcontext.view_y+4)*@zoom, b.w*@zoom, b.h*@zoom)
    set_color_box(b)
    draw_rectangle((b.x-@curcontext.view_x)*@zoom, (b.y-@curcontext.view_y+1)*@zoom, b.w*@zoom, b.h*@zoom)

    # current text position
    x = (b.x - @curcontext.view_x + 1)*@zoom
    y = (b.y - @curcontext.view_y + 1)*@zoom
    w_w = (b.x - @curcontext.view_x + b.w - @font_width)*@zoom
    w_h = (b.y - @curcontext.view_y + b.h - @font_height)*@zoom

    if @parent_widget and @parent_widget.bg_color_callback
      ly = 0
      b[:line_address].each { |a|
        if c = @parent_widget.bg_color_callback[a]
          draw_rectangle_color(c, (b.x-@curcontext.view_x)*@zoom, (1+b.y-@curcontext.view_y+ly*@font_height)*@zoom, b.w*@zoom, (@font_height*@zoom).ceil)
        end
        ly += 1
      }
    end

    if @caret_box == b
      draw_rectangle_color(:cursorline_bg, (b.x-@curcontext.view_x)*@zoom, (1+b.y-@curcontext.view_y+@caret_y*@font_height)*@zoom, b.w*@zoom, @font_height*@zoom)
    end

    return if @zoom < 0.99 or @zoom > 1.1
    # TODO dynamic font size ?

    # renders a string at current cursor position with a color
    # must not include newline
    render = lambda { |str, color|
      # function ends when we write under the bottom of the listing
      next if y >= w_h+2 or x >= w_w
      if @hl_word
        stmp = str
        pre_x = 0
        while stmp =~ /^(.*?)(\b#{Regexp.escape @hl_word}\b)/
          s1, s2 = $1, $2
          pre_x += s1.length * @font_width
          hl_x = s2.length * @font_width
          draw_rectangle_color(:hl_word, x+pre_x, y, hl_x, @font_height*@zoom)
          pre_x += hl_x
          stmp = stmp[s1.length+s2.length..-1]
        end
      end
      draw_string_color(color, x, y, str)
      x += str.length * @font_width
    }

    b[:line_text_col].each { |list|
      list.each { |s, c| render[s, c] }
      x = (b.x - @curcontext.view_x + 1)*@zoom
      y += @font_height*@zoom
    }

    if b == @caret_box and focus?
      cx = (b.x - @curcontext.view_x + 1 + @caret_x*@font_width)*@zoom
      cy = (b.y - @curcontext.view_y + 1 + @caret_y*@font_height)*@zoom
      draw_line_color(:caret, cx, cy, cx, cy+(@font_height-1)*@zoom)
    end
  end

  def gui_update
    @want_update_graph = true
    redraw
  end

  #
  # rebuild the code flow graph from @curcontext.roots
  # recalc the boxes w/h
  #
  def update_graph
    @want_update_graph = false

    ctx = @curcontext

    boxcnt = ctx.box.length
    arrcnt = ctx.box.inject(0) { |s, b| s + b.to.length + b.from.length }
    ctx.clear

    build_ctx(ctx)

    ctx.auto_arrange_boxes

    return if ctx != @curcontext

    if boxcnt != ctx.box.length or arrcnt != ctx.box.inject(0) { |s, b| s + b.to.length + b.from.length }
      zoom_all
    elsif @caret_box	# update @caret_box with a box at the same place
      bx = @caret_box.x + @caret_box.w/2
      by = @caret_box.y + @caret_box.h/2
      @caret_box = ctx.box.find { |cb| cb.x < bx and cb.x+cb.w > bx and cb.y < by and cb.y+cb.h > by }
    end
  end

  def load_dotfile(path)
    @want_update_graph = false
    @curcontext.clear
    boxes = {}
    new_box = lambda { |text|
      b = @curcontext.new_box(text, :line_text_col => [[[text, :text]]])
      b.w = text.length * @font_width
      b.h = @font_height
      b
    }
    max = File.size(path)
    i = 0
    File.open(path) { |fd|
      while l = fd.gets
        case l.strip
        when /^"?(\w+)"?\s*->\s*"?(\w+)"?;?$/
          b1 = boxes[$1] ||= new_box[$1]
          b2 = boxes[$2] ||= new_box[$2]
          b1.to   |= [b2]
          b2.from |= [b1]
        end
$stderr.printf("%.02f\r" % (fd.pos*100.0/max))  if (i += 1) & 0xff == 0
      end
    }
p boxes.length
    redraw
rescue Interrupt
p boxes.length
  end

  # create the graph objects in ctx
  def build_ctx(ctx)
    # graph : block -> following blocks in same function
    block_rel = {}

    todo = ctx.root_addrs.dup
    done = [:default, Expression::Unknown]
    while a = todo.shift
      a = @dasm.normalize a
      next if done.include? a
      done << a
      next if not di = @dasm.di_at(a)
      if not di.block_head?
        block_rel[di.block.address] = [a]
        @dasm.split_block(a)
      end
      block_rel[a] = []
      di.block.each_to_samefunc(@dasm) { |t|
        t = @dasm.normalize t
        next if not @dasm.di_at(t)
        todo << t
        block_rel[a] << t
      }
      block_rel[a].uniq!
    end

    # populate boxes
    addr2box = {}
    todo = ctx.root_addrs.dup
    todo.delete_if { |t| not @dasm.di_at(t) }	# undefined func start
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
        box = ctx.new_box a, :addresses => [], :line_text_col => [], :line_address => []
      end
      @dasm.decoded[a].block.list.each { |di_|
        box[:addresses] << di_.address
        addr2box[di_.address] = box
      }
      todo.concat block_rel[a]
    end

    # link boxes
    ctx.box.each { |b|
      next if not di = @dasm.decoded[b[:addresses].last]
      a = di.block.address
      next if not block_rel[a]
      block_rel[a].each { |t|
        ctx.link_boxes(b.id, t)
        b.direct_to = t if t == di.next_addr
      }
    }

    # calc box dimensions/text
    ctx.box.each { |b|
      colstr = []
      curaddr = nil
      line = 0
      render = lambda { |str, col| colstr << [str, col] }
      nl = lambda {
        b[:line_address][line] = curaddr
        b[:line_text_col][line] = colstr
        colstr = []
        line += 1
      }
      b[:addresses].each { |addr|
        curaddr = addr
        if di = @dasm.di_at(curaddr)
          if di.block_head?
            # render dump_block_header, add a few colors
            b_header = '' ; @dasm.dump_block_header(di.block) { |l| b_header << l ; b_header << ?\n if b_header[-1] != ?\n }
            b_header.strip.each_line { |l| l.chomp!
              col = :comment
              col = :label if l[0, 2] != '//' and l[-1] == ?:
              render[l, col]
              nl[]
            }
          end
          render["#{Expression[curaddr]}   ", :address] if @show_addresses
          render[di.instruction.to_s.ljust(di.comment ? 24 : 0), :instruction]
          render[' ; ' + di.comment.join(' ')[0, 64], :comment] if di.comment
          nl[]
        else
          # TODO real data display (dwords, xrefs, strings..)
          if label = @dasm.get_label_at(curaddr)
            render[label + ' ', :label]
          end
          s = @dasm.get_section_at(curaddr)
          render['db '+((s and s[0].data.length > s[0].ptr) ? Expression[s[0].read(1)[0]].to_s : '?'), :text]
          nl[]
        end
      }
      b.w = b[:line_text_col].map { |strc| strc.map { |s, c| s }.join.length }.max.to_i * @font_width + 2
      b.w += 1 if b.w % 2 == 0	# ensure boxes have odd width -> vertical arrows are straight
      b.h = line * @font_height
    }
  end

  def keypress_ctrl(key)
    case key
    when ?F
      @parent_widget.inputbox('text to search in curview (regex)', :text => @hl_word) { |pat|
        re = /#{pat}/i
        list = [['addr', 'instr']]
        @curcontext.box.each { |b|
          b[:line_text_col].zip(b[:line_address]) { |l, a|
            str = l.map { |s, c| s }.join
            list << [Expression[a], str] if str =~ re
          }
        }
        @parent_widget.list_bghilight("search result for /#{pat}/i", list) { |i| @parent_widget.focus_addr i[0] }
      }
    else return false
    end
    true
  end

  def keypress(key)
    case key
    when :left
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
    when :up
      if @caret_box
        if @caret_y > 0
          @caret_y -= 1
          update_caret
        elsif b = @curcontext.box.sort_by { |b_| -b_.y }.find { |b_| b_.y < @caret_box.y and
            b_.x < @caret_box.x+@caret_x*@font_width and
            b_.x+b_.w > @caret_box.x+(@caret_x+1)*@font_width }
          @caret_x += ((@caret_box.x-b.x)/@font_width).to_i
          @caret_y = b[:line_address].length-1
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
    when :right
      if @caret_box
        if @caret_x <= @caret_box[:line_text_col].map { |s| s.map { |ss, cc| ss }.join.length }.max
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
    when :down
      if @caret_box
        if @caret_y < @caret_box[:line_address].length-1
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
    when :pgup
      if @caret_box
        @caret_y = 0
        update_caret
      else
        @curcontext.view_y -= height/4/@zoom
        redraw
      end
    when :pgdown
      if @caret_box
        @caret_y = @caret_box[:line_address].length-1
        update_caret
      else
        @curcontext.view_y += height/4/@zoom
        redraw
      end
    when :home
      if @caret_box
        @caret_x = 0
        update_caret
      else
        @curcontext.view_x = @curcontext.box.map { |b_| b_.x }.min-10
        @curcontext.view_y = @curcontext.box.map { |b_| b_.y }.min-10
        redraw
      end
    when :end
      if @caret_box
        @caret_x = @caret_box[:line_text_col][@caret_y].to_a.map { |ss, cc| ss }.join.length
        update_caret
      else
        @curcontext.view_x = [@curcontext.box.map { |b_| b_.x+b_.w }.max-width/@zoom+10, @curcontext.box.map { |b_| b_.x }.min-10].max
        @curcontext.view_y = [@curcontext.box.map { |b_| b_.y+b_.h }.max-height/@zoom+10, @curcontext.box.map { |b_| b_.y }.min-10].max
        redraw
      end

    when :delete
      @selected_boxes.each { |b_|
        @curcontext.box.delete b_
        b_.from.each { |bb| bb.to.delete b_ }
        b_.to.each { |bb| bb.from.delete b_ }
      }
      redraw

    when ?a
      puts 'autoarrange'
      @curcontext.auto_arrange_boxes
      redraw
      puts 'autoarrange done'
    when ?u
      gui_update

    when ?R
      load __FILE__
    when ?S	# reset
      @curcontext.auto_arrange_init(@selected_boxes.empty? ? @curcontext.box : @selected_boxes)
      puts 'reset', @curcontext.dump_layout, ''
      zoom_all
      redraw
    when ?T	# step auto_arrange
      @curcontext.auto_arrange_step
      puts @curcontext.dump_layout, ''
      zoom_all
      redraw
    when ?L	# post auto_arrange
      @curcontext.auto_arrange_post
      zoom_all
      redraw
    when ?V	# shrink
      @selected_boxes.each { |b_|
        dx = (b_.from + b_.to).map { |bb| bb.x+bb.w/2 - b_.x-b_.w/2 }
        dx = dx.inject(0) { |s, xx| s+xx }/dx.length
        b_.x += dx
      }
      redraw
    when ?I	# create arbitrary boxes/links
      if @selected_boxes.empty?
        @fakebox ||= 0
        b = @curcontext.new_box "id_#@fakebox",
          :addresses => [], :line_address => [],
          :line_text_col => [[["  blublu #@fakebox", :text]]]
        b.w = @font_width * 15
        b.h = @font_height * 2
        b.x = rand(200) - 100
        b.y = rand(200) - 100
        
        @fakebox += 1
      else
        b1, *bl = @selected_boxes
        bl = [b1] if bl.empty?	# loop
        bl.each { |b2|
          if b1.to.include? b2
            b1.to.delete b2
            b2.from.delete b1
          else
            b1.to << b2
            b2.from << b1
        end
      }
      end
      redraw

    when ?1	# (numeric) zoom to 1:1
      if @zoom == 1.0
        zoom_all
      else
        @curcontext.view_x += (width/2 / @zoom - width/2)
        @curcontext.view_y += (height/2 / @zoom - height/2)
        @zoom = 1.0
      end
      redraw
    when :insert		# split curbox at @caret_y
      if @caret_box and a = @caret_box[:line_address][@caret_y] and @dasm.decoded[a]
        @dasm.split_block(a)
        @curcontext.keep_split ||= []
        @curcontext.keep_split |= [a]
        gui_update
        focus_addr a
      end
    else return false
    end
    true
  end

  # find a suitable array of graph roots, walking up from a block (function start/entrypoint)
  def dasm_find_roots(addr)
    todo = [addr]
    done = []
    roots = []
    default_root = nil
    while a = todo.shift
      next if not di = @dasm.di_at(a)
      b = di.block
      a = b.address
      if done.include? a
        default_root ||= a
        next
      end
      done << a
      newf = []
      b.each_from_samefunc(@dasm) { |f| newf << f }
      if newf.empty?
        roots << b.address
      else
        todo.concat newf
      end
    end
    roots << default_root if roots.empty? and default_root

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

  # focus on addr
  # addr may be a dasm label, dasm address, dasm address in string form (eg "0DEADBEEFh")
  # addr must point to a decodedinstruction
  # if the addr is not found in curcontext, the code flow is walked up until a function
  # start or an entrypoint is found, then the graph is created from there
  # will call gui_update then
  def focus_addr(addr, can_update_context=true)
    return if @parent_widget and not addr = @parent_widget.normalize(addr)
    return if not @dasm.di_at(addr)

    # move window / change curcontext
    if b = @curcontext.box.find { |b_| b_[:line_address].index(addr) }
      @caret_box, @caret_x, @caret_y = b, 0, b[:line_address].rindex(addr)
      @curcontext.view_x += (width/2 / @zoom - width/2)
      @curcontext.view_y += (height/2 / @zoom - height/2)
      @zoom = 1.0

      focus_xy(b.x, b.y + @caret_y*@font_height)
      update_caret
    elsif can_update_context
      @curcontext = Graph.new 'testic'
      @curcontext.root_addrs = dasm_find_roots(addr)
      @want_focus_addr = addr
      gui_update
    else
      return
    end
    true
  end

  def focus_xy(x, y)
    if not @curcontext.view_x or @curcontext.view_x*@zoom + width*3/4 < x or @curcontext.view_x*@zoom > x
      @curcontext.view_x = (x - width/5)/@zoom
      redraw
    end
    if not @curcontext.view_y or @curcontext.view_y*@zoom + height*3/4 < y or @curcontext.view_y*@zoom > y
      @curcontext.view_y = (y - height/5)/@zoom
      redraw
    end
  end

  # hint that the caret moved
  # redraw, change the hilighted word
  def update_caret
    return if not @caret_box or not @caret_x or not l = @caret_box[:line_text_col][@caret_y]
    l = l.map { |s, c| s }.join
    @parent_widget.focus_changed_callback[] if @parent_widget and @parent_widget.focus_changed_callback and @oldcaret_y != @caret_y
    update_hl_word(l, @caret_x)
    redraw
  end

  def current_address
    @caret_box ? @caret_box[:line_address][@caret_y] : @curcontext.root_addrs.first
  end
end
end
end
