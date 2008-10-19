module Msf
  module Ui
    module Gtk2

      #
      # Model using for rendering a textview
      #
      class SkeletonTextBuffer < Gtk::TextBuffer

        include Msf::Ui::Gtk2::MyControls

        def initialize
          super()
          
          self.create_tag("_",
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'left_margin' => 5
          )
          
          # Red
          self.create_tag("red",
          :'foreground' => 'red',
          :'left_margin' => 5
          )
          self.create_tag("red_bold",
          :'foreground' => 'red',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'left_margin' => 5
          )
          self.create_tag("red_bold_cust",
          :'foreground' => 'red',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'left_margin' => 100
          )
          
          # ForestGreen
          self.create_tag("forestgreen",
          :'foreground' => 'ForestGreen',
          :'left_margin' => 5
          )
          self.create_tag("forestgreen_bold",
          :'foreground' => 'ForestGreen',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'left_margin' => 5
          )
          self.create_tag("forestgreen_bold_cust",
          :'foreground' => 'ForestGreen',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'left_margin' => 100
          )
          self.create_tag("forestgreen_bold_center",
          :'foreground' => 'ForestGreen',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'justification' => Gtk::JUSTIFY_CENTER
          )
          
          # RosyBrown
          self.create_tag("rosybrown",
          :'foreground' => 'RosyBrown',
          :'left_margin' => 5
          )
          self.create_tag("rosybrown_bold",
          :'foreground' => 'RosyBrown',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'left_margin' => 5
          )
          self.create_tag("rosybrown_bold_cust",
          :'foreground' => 'RosyBrown',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'left_margin' => 100
          )
          
          # Blue
          self.create_tag("blue",
          :'foreground' => 'blue',
          :'left_margin' => 5
          )
          self.create_tag("blue_bold",
          :'foreground' => 'blue',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'left_margin' => 5
          )
          self.create_tag("blue_bold_cust",
          :'foreground' => 'blue',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'underline' => Pango::UNDERLINE_SINGLE,
          :'left_margin' => 5
          )
          
          # Black
          self.create_tag("black_italic_wrap",
          :'style' => Pango::FontDescription::STYLE_ITALIC,
          :'wrap_mode' => Gtk::TextTag::WRAP_WORD,
          :'left_margin' => 5
          )
          self.create_tag("black_bold",
          :'foreground' => 'black',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'left_margin' => 5
          )
          # Black
          self.create_tag("black_wrap",
          :'wrap_mode' => Gtk::TextTag::WRAP_WORD,
          :'left_margin' => 5
          )


          self.create_tag("black_center",
          :'foreground' => 'black',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'justification' => Gtk::JUSTIFY_CENTER
          )
		  		            
          # White
          self.create_tag("white",
          :'foreground' => 'white',
          :'left_margin' => 5
          )
          self.create_tag("white_italic",
          :'foreground' => 'white',
          :'style' => Pango::FontDescription::STYLE_ITALIC,
          :'left_margin' => 5
          )
          self.create_tag("white_bold",
          :'foreground' => 'white',
          :'weight' => Pango::FontDescription::WEIGHT_BOLD,
          :'left_margin' => 5
          )
          self.create_tag("white_wrap",
          :'foreground' => 'white',
          :'wrap_mode' => Gtk::TextTag::WRAP_WORD,
          :'left_margin' => 5
          )
        end

      end

    end
  end
end