#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm GUI plugin: dumps the text of the current widget to a text file on 'D' keypress
# the dump is appended to the file if it exists
# works on the listing view (current screen),
# on the decompiled view (current function),
# on the graph view (selected blocks, in selection order)

if gui
  gui.keyboard_callback[?D] = lambda { |a|
    cv = gui.curview
    if t = cv.instance_variable_get('@line_text')
      gui.savefile('dump file') { |f|
        File.open(f, 'a') { |fd| fd.puts t }
      }
    elsif s = cv.instance_variable_get('@selected_boxes')
      if s.empty?
        gui.messagebox('select boxes (ctrl+click)')
        next
      end
      gui.savefile('dump file') { |f|
        File.open(f, 'a') { |fd|
          s.each { |box|
            fd.puts box[:line_text_col].map { |strc| strc.transpose[0].join }
          }
          fd.puts
        }
      }
    end
  }
end
