module Msf
module Ui
module Wx

class MyApp < ::Wx::App
	
	include Msf::Ui::Wx::MyControls

	def on_init()
		@frame  = MyFrame.new(
			nil, 
			"Metasploit Framework v#{Msf::Framework::Version} GUI", 
			-1, 
			-1,
			800, 
			600
		)
		
		@frame.create_status_bar(1)

		# Create the file menu
		file_menu = ::Wx::Menu.new
		file_menu.append(APP_MENU_RELOAD, "&Reload Modules")
		file_menu.append(APP_MENU_QUIT, "&Quit Metasploit Framework")

		help_menu = ::Wx::Menu.new
		help_menu.append(APP_MENU_ABOUT, "&About", "About the Metasploit Framework")

		# Create the meny bar
		menu_bar = ::Wx::MenuBar.new
		menu_bar.append(file_menu, "&File")
		menu_bar.append(help_menu, "&Help")

		# Associate the menu bar with the @frame
		@frame.set_menu_bar(menu_bar)	

		@frame.show(TRUE)

		@frame.set_status_text(
			"Loaded " + 
			framework.stats.num_exploits.to_s + " exploits, " +
			framework.stats.num_payloads.to_s + " payloads, " +
			framework.stats.num_encoders.to_s + " encoders, " +
			framework.stats.num_nops.to_s + " nops, and " +
			framework.stats.num_auxiliary.to_s + " auxiliary"
		)

		set_top_window(@frame)
	end		
end

end
end
end
