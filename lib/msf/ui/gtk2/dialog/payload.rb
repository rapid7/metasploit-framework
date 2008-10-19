module Msf
  module Ui
    module Gtk2
      
      class MsfDialog

        ##
        # Class for the payload rendering
        # title: the payload refname
        # payload: the generated payload
        ##
        class Payload < Msf::Ui::Gtk2::SkeletonView
          def initialize(title, payload)
            @buffer = Gtk::TextBuffer.new
            super(title, @buffer)

            colorize()
            display(payload)

            self.default_response = Gtk::Dialog::RESPONSE_NONE
            show_all and run
            destroy
          end

          #
          # Display the generated payload with color
          #
          def display(payload)
            filter = /^\#/
            @buffer.delete(*@buffer.bounds)
            start = @buffer.get_iter_at_offset(0)

            payload.each do |line|
              if ( line.match(filter) )
                @buffer.insert_with_tags(start, line, 'comments')
              else
                @buffer.insert_with_tags(start, line, '_')
              end
            end
          end

          #
          # Create tags for the syntax color
          #
          def colorize
            @buffer.create_tag("comments",
            :'foreground' => 'RosyBrown',
            :'weight' => Pango::FontDescription::WEIGHT_BOLD
            )

            @buffer.create_tag("_",
            :'weight' => Pango::FontDescription::WEIGHT_BOLD
            )
          end
        end
        
      end
      
    end
  end
end