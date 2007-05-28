module Msf
  module Ui
    module Gtk2

      ##
      # This class describe all tags and behaviour for module view rendering
      # To initialize, a Gtk::TextBuffer must be passed in argument
      # TODO: Add a pixmap for platform
      #
      class MyModuleView
        def initialize(buffer)
          @buffer = buffer
        end

        def insert_module(obj)
          @buffer.delete(*@buffer.bounds)
          start = @buffer.get_iter_at_offset(0)
          @buffer.insert_with_tags(start, "Type : ", '_')
          @buffer.insert_with_tags(start, obj.type + "\n", 'red_bold_cust')
          @buffer.insert_with_tags(start, "Author : ", "_")
          @buffer.insert_with_tags(start, obj.author_to_s + "\n", 'forestgreen_bold_cust')
          @buffer.insert_with_tags(start, "Path : ", "_")
          @buffer.insert_with_tags(start, obj.refname + "\n\n", 'rosybrown_bold_cust')
          @buffer.insert_with_tags(start, "External Reference :\n", "_")
          extref = ""
          obj.references.each do |refs|
            extref << refs.to_s + "\n"
          end
          @buffer.insert_with_tags(start, extref + "\n", 'blue_bold_cust')
          @buffer.insert_with_tags(start, "Description :", '_')

          # Ugly ... ;-( but crafty
          desc = ""
          obj.description.each_line do |line|
            desc << line.strip + "\n"
          end
          @buffer.insert_with_tags(start, desc, 'black_italic_wrap')
        end
      end

    end
  end
end
