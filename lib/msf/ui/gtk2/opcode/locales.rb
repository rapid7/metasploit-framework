module Msf
  module Ui
    module Gtk2

      #
      # Gtk2 Interface for Metasploit Opcodes database
      #
      class MsfOpcode

        # Create the opcode client instance
        $client = Rex::Exploitation::OpcodeDb::Client.new

        #
        # Opcodes locales
        #
        class Locales < Msf::Ui::Gtk2::SkeletonOpcode
          def initialize
            comment = "Locales currently supported by the database:"

            # call the parent
            super("Locales", comment)

            self.set_default_size(500, 230)

            textview = Gtk::TextView.new
            textbuffer = Gtk::TextBuffer.new
            stuff.pack_start(textview, true, true, 0)

            locales = "\n"
            $client.locales.each do |locale|
              locales << " -" + locale.name + "\n"
            end

            textbuffer.set_text( locales )

            textview.set_buffer(textbuffer)
            textview.set_editable(false)
            textview.set_cursor_visible(false)

            show_all and run
            destroy
          end
        end
        
      end

    end
  end
end
