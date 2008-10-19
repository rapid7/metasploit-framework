module Msf
module Ui
module Gtk2

	##
	# This class describe all tags and behaviour for module view rendering
	# To initialize, a Gtk::TextBuffer must be passed in argument
	# TODO: Add a pixmap for platform
	#
	class MyModuleView
	
		module TagHref
			attr_accessor :href
		end
	
		def initialize(buffer)
			@buffer = buffer
		end

		def insert_help(name)
			@buffer.delete(*@buffer.bounds)
			start = @buffer.get_iter_at_offset(0)

			help_intro = %Q{
				This interface can be used in either wizard-mode or console-mode. To start the
				wizard, browse to a module in the list above, and double-click its name. To 
				view the source code of a module, right-click its name and select the View Code
				option. If you prefer to work in a msfconsole interface instead, select the 
				Console option from the Window menu (or just press Control+O). Have fun!
			}

			@buffer.insert_with_tags(start, "\nWelcome to the Metasploit Framework GUI!\n\n", "black_center")	
			@buffer.insert_with_tags(start, help_intro.gsub(/\s+/, " ").strip, "black_wrap")	
		end

		def insert_module(obj)
			@buffer.delete(*@buffer.bounds)
			start = @buffer.get_iter_at_offset(0)
			
			credit = [ *obj.author ].map {|a| "#{a.name} (#{a.email})" }.join(" and ")
			
			# The description goes first
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
			desc.strip!
			
			if(desc.length > 0 and not (desc[-1]  >= 0x21 and desc[-1] <= 0x2e) )
				desc << "."
			end
			
			@buffer.insert_with_tags(start, "Module: ", "_")
			@buffer.insert_with_tags(start, "#{obj.fullname}\n\n", "black_wrap")
			
			@buffer.insert_with_tags(start, 
				desc + " This #{obj.type} module was written by #{credit}\n\n",
				"black_wrap"
			)


			if(obj.references.length > 0)
				@buffer.insert_with_tags(start, "References:\n", "_")

				obj.references.each do |ref|
					tag = @buffer.create_tag(nil, {
						'foreground' => 'blue',
						'underline' => Pango::AttrUnderline::SINGLE,
						'left_margin' => 25
					})
					tag.extend(TagHref)
					tag.href = ref.to_s				
					@buffer.insert_with_tags(start, ref.to_s + "\n", tag)
				end
			
				@buffer.insert_with_tags(start, "\n")
			end
			
		end
	end

end
end
end