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
          @buffer.create_tag("_",
          :'weight' => Pango::FontDescription::WEIGHT_BOLD
          )
          @buffer.create_tag("type",
          :'foreground' => 'red',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'left_margin' => 100
          )
          @buffer.create_tag("author",
          :'foreground' => 'ForestGreen',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'left_margin' => 100
          )
          @buffer.create_tag("refname",
          :'foreground' => 'RosyBrown',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'left_margin' => 100
          )
          @buffer.create_tag("reference",
          :'foreground' => 'blue',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'underline' => Pango::UNDERLINE_SINGLE,
          :'left_margin' => 100
          )
          @buffer.create_tag("description",
          :'style' => Pango::FontDescription::STYLE_ITALIC,
          :'wrap_mode' => Gtk::TextTag::WRAP_WORD
          )
        end

        def insert_module(obj)
          @buffer.delete(*@buffer.bounds)
          start = @buffer.get_iter_at_offset(0)
          @buffer.insert_with_tags(start, "Type : ", "_")
          @buffer.insert_with_tags(start, obj.type + "\n", 'type')
          @buffer.insert_with_tags(start, "Author : ", "_")
          @buffer.insert_with_tags(start, obj.author_to_s + "\n", 'author')
          @buffer.insert_with_tags(start, "Path : ", "_")
          @buffer.insert_with_tags(start, obj.refname + "\n\n", 'refname')
          @buffer.insert_with_tags(start, "External Reference :\n", "_")
          extref = ""
          obj.references.each do |refs|
            extref << refs.to_s + "\n"
          end
          @buffer.insert_with_tags(start, extref + "\n", 'reference')
          @buffer.insert_with_tags(start, "Description :", '_')

          # Ugly ... ;-( but crafty
          desc = ""
          obj.description.each_line do |line|
            desc << line.strip + "\n"
          end
          @buffer.insert_with_tags(start, desc, 'description')
        end
      end

    end
  end
end
