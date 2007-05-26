module Msf
  module Ui
    module Gtk2

      #
      #
      #
      class SkeletonType < Gtk::VBox

        def initialize
          super(false, 0)
        end

        #
        #
        #
        def pack_description(description)
          label = Gtk::Label.new
          label.set_alignment(0, 1)
          label.set_markup("<i>#{description}</i>")
          self.pack_start(label, false, false, 0)
        end

      end

    end
  end
end
