module Msf
  module Ui
    module Gtk2
      ##
      # Gtk2 Interface for msfopcode
      ##

      #
      # Skeleton for opcodes stuff
      #
      class SkeletonOpcode < Gtk::Dialog

        include Msf::Ui::Gtk2::MyControls

        attr_accessor :comment, :stuff

        def initialize(title, comments, buttons=[[ Gtk::Stock::CLOSE, Gtk::Dialog::RESPONSE_NONE ]])
          super("", $gtk2driver.main, Gtk::Dialog::DESTROY_WITH_PARENT, *buttons)

          # Style
          console_style = File.join(driver.resource_directory, 'style', 'opcode.rc')
          Gtk::RC.parse(console_style)

          self.border_width = 6
          self.resizable = true
          self.has_separator = true
          self.vbox.spacing = 12
          self.vbox.set_homogeneous(false)
          self.title = title
          self.set_default_size(500, 400)

          @comment = Gtk::Label.new
          @comment.set_alignment(0, 0)
          @comment.set_markup("<b>#{comments}</b>")
          self.vbox.pack_start(@comment, false, false, 0)

          @stuff = Gtk::VBox.new(false, 10)
          self.vbox.pack_start(@stuff, true, true, 0)
        end
      end

    end
  end
end