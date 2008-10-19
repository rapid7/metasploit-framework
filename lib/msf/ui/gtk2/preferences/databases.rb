module Msf
  module Ui
    module Gtk2

      class MsfPreferences

        #
        # This class is dedicated to perform database configuration
        #
        class Databases

          include Msf::Ui::Gtk2::MyControls

          def initialize
            @page = Gtk::VBox.new
            warning = Gtk::Label.new
            warning.set_markup("Review your configuration before clicking the <b>apply</b> button")
            @page.pack_start(warning, true, true, 0)
            
            bb = Gtk::HButtonBox.new()
            test = Gtk::Button.new(Gtk::Stock::CONNECT)
            modify = Gtk::Button.new(Gtk::Stock::EDIT)
            rebuild = Gtk::Button.new(Gtk::Stock::EXECUTE)
            
            test.signal_connect('clicked') do
             MsfDialog::Error.new($gtk2driver.main, "Not available")
            end
            
            modify.signal_connect('clicked') do
              MsfDialog::Error.new($gtk2driver.main, "Not available")
            end
            
            rebuild.signal_connect('clicked') do
              MsfDialog::Error.new($gtk2driver.main, "Not available")
            end
            
            bb.pack_start(test, false, false)
            bb.pack_start(modify, false, false)
            bb.pack_start(rebuild, false, false)
            
            @page.pack_start(bb, false, false, 0)
          end
          
          def page
            return @page
          end
          
          def label
            return Gtk::Label.new("Databases")
          end
          
          def type
          end
          

        end

      end
    end
  end
end