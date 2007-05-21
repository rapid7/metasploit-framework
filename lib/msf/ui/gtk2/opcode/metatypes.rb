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
        # Opcodes meta types
        #
        class Metatypes < Msf::Ui::Gtk2::SkeletonOpcode
          def initialize
            comment = "Opcode meta types currently supported by the database :"

            # call the parent
            super("Metatypes", comment)

            textview = Gtk::TextView.new
            textbuffer = Gtk::TextBuffer.new
            stuff.pack_start(textview, true, true, 0)

            mts = "\n"
            $client.meta_types.each do |mt|
              mts << " - " + mt.name + "\n"
            end

            textbuffer.set_text( mts )

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
