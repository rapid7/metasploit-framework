#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin: create a function to export the currently displayed
# dasm graph to a .svg file
# in the gui, type E to export. Tested only for graph-style view, *may* work in other cases

raise 'gui only' if not gui

def graph_to_svg
  gw = gui.curview.dup
  class << gw
    attr_accessor :svgbuf, :svgcol
    def draw_color(col)
      col = @default_color_association.fetch(col, col)
      col = BasicColor.fetch(col, col)
      @svgcol = "##{col}"
    end

    def draw_line(x1, y1, x2, y2)
      bb(x1, y1, x2, y2)
      svgbuf << %Q{<line x1="#{x1}" y1="#{y1}" x2="#{x2}" y2="#{y2}" stroke="#{@svgcol}" />\n}
    end
    def draw_rectangle(x, y, w, h)
      bb(x, y, x+w, y+h)
      svgbuf << %Q{<rect x="#{x}" y="#{y}" width="#{w}" height="#{h}" fill="#{@svgcol}" />\n}
    end
    def draw_string(x, y, str)
      bb(x, y, x+str.length*@font_width, y+@font_height)
      stre = str.gsub('<', '&lt;').gsub('>', '&gt;')
      svgbuf << %Q{<text x="#{(0...str.length).map { |i| x+i*@font_width }.join(',')}" y="#{y+@font_height*0.7}" stroke="#{@svgcol}">#{stre}</text>\n}
    end

    def draw_rectangle_color(c, *a)
      draw_color(c)
      draw_rectangle(*a)
    end
    def draw_line_color(c, *a)
      draw_color(c)
      draw_line(*a)
    end
    def draw_string_color(c, *a)
      draw_color(c)
      draw_string(*a)
    end

    def focus?; false; end
    def view_x; @svgvx ||= @curcontext.boundingbox[0]-20; end
    def view_y; @svgvy ||= @curcontext.boundingbox[1]-20; end
    def width;  @svgvw ||= (@curcontext ? (@curcontext.boundingbox[2]-@curcontext.boundingbox[0])*@zoom+20 : 800); end
    def height; @svgvh ||= (@curcontext ? (@curcontext.boundingbox[3]-@curcontext.boundingbox[1])*@zoom+20 : 600); end
    def svgcuraddr; @curcontext ? @curcontext.root_addrs.first : current_address; end

    # drawing bounding box (for the background rectangle)
    attr_accessor :bbx, :bby, :bbxm, :bbym
    def bb(x1, y1, x2, y2)
      @bbx  = [x1, x2, @bbx].compact.min
      @bbxm = [x1, x2, @bbxm].compact.max
      @bby  = [y1, y2, @bby].compact.min
      @bbym = [y1, y2, @bbym].compact.max
    end
  end
  ret = gw.svgbuf = ''
  gw.paint

  ret[0, 0] = <<EOS
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 20010904//EN" 
  "http://www.w3.org/TR/2001/REC-SVG-20010904/DTD/svg10.dtd">
<svg xmlns="http://www.w3.org/2000/svg" font-family="courier, monospace">
<desc>Graph of #{get_label_at(gw.svgcuraddr) || Expression[gw.svgcuraddr]}</desc>
<rect x="#{gw.bbx-10}" y="#{gw.bby-10}" width="#{gw.bbxm-gw.bbx+20}" height="#{gw.bbym-gw.bby+20}" fill="#{gw.draw_color(:background)}" />"
EOS
  ret << %Q{</svg>}
end

gui.keyboard_callback[?E] = lambda { |*a|
  gui.savefile('svg target') { |f|
    svg = graph_to_svg
    File.open(f, 'w') { |fd| fd.write svg }
  }
  true
}
