module Msf
  module Ui
    module Gtk2

      class MsfWindow

        #
        # This class performs a Gtk::Window to display logs from framework
        #
        class Logs < Msf::Ui::Gtk2::SkeletonBasic

          include Msf::Ui::Gtk2::MyControls

          def initialize
            console_style = File.join(driver.resource_directory, 'style', 'console.rc')
            Gtk::RC.parse(console_style)
            
            # call the parent
            super("Metasploit Framework Logs")
            
            # Define the size and border
            set_default_size(400, 400)
            set_border_width(10)

            # Main hbox
            vbox = Gtk::VBox.new(false, 0)
            add(vbox)
            
            textview = Gtk::TextView.new($gtk2driver.log_text.buffer)
            textview.set_editable(false)
            
            sw = Gtk::ScrolledWindow.new()
            sw.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
            vbox.pack_start(sw, true, true, 0)
            
            sw.add(textview)
            
            show_all
          end

        end

      end

    end
  end
end