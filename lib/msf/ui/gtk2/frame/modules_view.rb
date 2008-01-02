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
		end

		def insert_module(obj)
			@buffer.delete(*@buffer.bounds)
			start = @buffer.get_iter_at_offset(0)
			@buffer.insert_with_tags(start, "Type: ", '_')
			@buffer.insert_with_tags(start, obj.class.to_s + "\n", 'red_bold_cust')
			@buffer.insert_with_tags(start, "Author(s): ", "_")
			@buffer.insert_with_tags(start, obj.author_to_s + "\n", 'forestgreen_bold_cust')
			@buffer.insert_with_tags(start, "Path: ", "_")
			@buffer.insert_with_tags(start, obj.refname + "\n\n", 'rosybrown_bold_cust')


			if(obj.references.length > 0)
				@buffer.insert_with_tags(start, "References:\n", "_")

				obj.references.each do |ref|
					@buffer.insert_with_tags(start, ref.to_s + "\n", 'blue_bold_cust')
				end
			
				@buffer.insert_with_tags(start, "\n")
			end
			
			
			@buffer.insert_with_tags(start, "Description:\n", '_')

			# Ugly ... ;-( but crafty
			desc = ""
			obj.description.each_line do |line|
				line.strip!
				if (line.length == 0)
					desc << "\n\n" if desc.length > 0
				else
					desc << " " if (desc.length > 0 and desc[-1,1] != "\n")
					desc << line.gsub(/\s+/, " ").strip
				end
			end
			
			@buffer.insert_with_tags(start, Rex::Text.wordwrap(desc, 0, 70), "black_wrap")
		end
	end

	end
end
end
