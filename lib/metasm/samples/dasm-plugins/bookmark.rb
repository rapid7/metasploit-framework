#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm GUI plugin: 
# pops a list of bookmarked functions
# also allows the custom coloration of blocks/functions

if gui
  class ColorWindow < Metasm::Gui::ToolWindow
    def initialize_window(&b)
      self.title = 'pick a color'
      self.widget = ColorWidget.new(&b)
    end
  end

  class ColorWidget < Metasm::Gui::DrawableWidget
    attr_accessor :ph, :pw
    def initialize_widget(&b)
      super()
      @action = b
      @pw = 3
      @ph = 8
    end

    def initial_size
      [@pw*256, @ph*16]
    end

    def paint
      0x100.times { |x|
        cx = x
        if x & 0x10 > 0
          cx = (x&0xf0) + (15-(x&0xf))
        end
        0x10.times { |y|
          col = '%02x%x' % [cx, y]
          draw_rectangle_color(col, x*@pw, y*@ph, @pw, @ph)
        }
      }
    end

    def xy_to_col(x, y)
      x = x.to_i / @pw
      y = y.to_i / @ph
      if x >=0 and y >= 0 and x <= 0xff and y <= 0xf
        if x & 0x10 > 0
          x = (x&0xf0) + (15-(x&0xf))
        end
        col = '%02x%x' % [x, y]
        toplevel.title = "color #{col}"
        col
      end
    end

    def mousemove(x, y)
      xy_to_col(x, y)
    end

    def mouserelease(x, y)
      if c = xy_to_col(x, y)
        toplevel.destroy
        @action.call(c)
      end
    end
  end

  # list of user-specified addrs
  @bookmarklist = []
  # every single addr => color
  @bookmarkcolor = {}

  obg = gui.bg_color_callback	# chain old callback
  gui.bg_color_callback = lambda { |a|
    if obg and col = obg[a]
      col
    else
      # least priority
      @bookmarkcolor[a]
    end
  }

  popbookmarks = lambda { |*a|
    list = [['address', 'color']] + @bookmarklist.map { |bm| [Expression[bm].to_s, @bookmarkcolor[bm].to_s] }
    listcolcb = lambda { |e| [nil, @bookmarkcolor[Expression.parse_string(e[0]).reduce]] }
    gui.listwindow('bookmarks', list, :color_callback => listcolcb) { |e| gui.focus_addr(e[0]) }
  }

  # an api to bookmark a function
  def bookmark_function(addr, color)
    return if not fa = find_function_start(addr)
    list = function_blocks(fa).map { |k, v| block_at(k).list.map { |di| di.address } }.flatten
    bookmark_addrs list, color
  end
  def bookmark_addrs(list, color)
    al = [list].flatten.uniq
    gui.session_append("dasm.bookmark_addrs(#{list.inspect}, #{color.inspect})")
    @bookmarklist |= [al.min]
    al.each { |a| @bookmarkcolor[a] = color }
    gui.gui_update
  end
  def bookmark_delete_function(addr)
    return if not fa = find_function_start(addr)
    list = function_blocks(fa).map { |k, v| block_at(k).list.map { |di| di.address } }.flatten
    bookmark_delete list
  end
  def bookmark_delete(list)
    @bookmarklist -= list
    list.each { |a| @bookmarkcolor.delete a }
  end
  def bookmark_delete_color(col)
    @bookmarkcolor.delete_if { |k, v| if v == col ; @bookmarklist.delete k ; true end }
  end


  w = gui.toplevel
  w.addsubmenu(w.find_menu('Views'), '_Bookmarks', popbookmarks)
  w.update_menu
  gui.keyboard_callback[?B] = popbookmarks
  gui.keyboard_callback[?C] = lambda { |a|
    if s = gui.curview.instance_variable_get('@selected_boxes') and not s.empty?
      al = s.map { |b| b[:line_address] }
    elsif fa = find_function_start(gui.curaddr)
      al = function_blocks(fa).map { |k, v| block_at(k).list.map { |di| di.address } }
    else
      next
    end
    # XXX also prompt for comment/bookmark name ?
    ColorWindow.new(gui.toplevel) { |col| bookmark_addrs(al, col) }
  }
end
