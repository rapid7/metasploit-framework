module Msf
module Ui
module Wx

	# ID generator for Wx controls
	class IDGen
		@@last_id = 1000
		def self.alloc
			@@last_id += 1
		end
	end
	
	# Menu items in the main application
	APP_MENU_QUIT   = IDGen.alloc
	APP_MENU_ABOUT  = IDGen.alloc
	APP_MENU_RELOAD = IDGen.alloc
	
	# Tree controls
	FRAME_TREE_MODULES = IDGen.alloc
	
	# Notebook contrls
	NOTE_MODULES = IDGen.alloc
	NOTE_CONSOLE = IDGen.alloc
	
	# Panels
	PANEL_INFO = IDGen.alloc
	
	# Icons
	FRAME_ICONS_MODULES   = 0
	FRAME_ICONS_EXPLOITS  = 1
	FRAME_ICONS_AUXILIARY = 2
	FRAME_ICONS_PAYLOADS  = 3
	FRAME_ICONS_ENCODERS  = 4
	FRAME_ICONS_NOPS      = 5
	FRAME_ICONS_MOD_EXPLOIT    = 6
	FRAME_ICONS_MOD_AUXILIARY  = 6
	FRAME_ICONS_MOD_PAYLOAD    = 7
	FRAME_ICONS_MOD_ENCODER    = 7
	FRAME_ICONS_MOD_NOP        = 7	
end
end
end
