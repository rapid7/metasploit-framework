module Msf
module Ui
module Gtk2

class MsfWindow

	#
	# This class performs a Gtk::Window to display logs from framework
	#
	class CodeView < Msf::Ui::Gtk2::SkeletonBasic

		include Msf::Ui::Gtk2::MyControls

		def initialize(m)

			# call the parent
			super("Source Code of #{m.type.capitalize} #{m.refname}")

			# Define the size and border
			set_default_size(600, 480)
			set_border_width(10)

			# Main hbox
			vbox = Gtk::VBox.new(false, 0)
			add(vbox)

			textview = Gtk::TextView.new
			textview.set_editable(false)

			sw = Gtk::ScrolledWindow.new()
			sw.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
			vbox.pack_start(sw, true, true, 0)

			sw.add(textview)


			buff = textview.buffer
			fixr = buff.create_tag("fixr", 
				{ 
					"font" => "Courier"
				}
			)
		
			buff.insert(buff.end_iter, File.read(m.file_path), "fixr")
			
			show_all
		end

	end

end

end
end
end
