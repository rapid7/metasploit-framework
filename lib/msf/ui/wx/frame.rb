module Msf
module Ui
module Wx

class MyFrame < ::Wx::Frame
	
	def initialize(frame, title, x, y, w, h, driver)
		super(frame, -1, title, ::Wx::Point.new(x, y), ::Wx::Size.new(w, h))

		# Keep a reference to the driver instance
		@driver = driver
		
		# Reduce flicker on scroll
		set_background_colour(::Wx::Colour.new(255, 255, 255))

        # Give it an icon
        set_icon(@driver.get_icon('msfwx.xpm'))
		
		evt_menu(APP_MENU_QUIT)  {on_quit}
		evt_menu(APP_MENU_ABOUT) {on_about}
		
		# Load the module tree
		::Wx::BusyCursor.busy do |x|
			my_create_module_tree()
		end
	end

	# Shortcut for accessing the framework instance
	def framework
		@driver.framework
	end
	
	def on_quit
		close(TRUE)
	end
	
	def on_about
		message_box("Metasploit Framework GUI", "About Metasploit Framework", OK|CENTRE)
	end
	
	def my_create_module_tree()
		tree_style = 
#			::Wx::TR_TWIST_BUTTONS |
#			::Wx::TR_HAS_BUTTONS |		
			::Wx::SUNKEN_BORDER |
			::Wx::TR_NO_LINES |
			::Wx::TR_FULL_ROW_HIGHLIGHT |
			::Wx::TR_DEFAULT_STYLE 			

		@m_tree_modules = Msf::Ui::Wx::MyControls::MyModuleTree.new(
			self,
			FRAME_TREE_MODULES,
			::Wx::DEFAULT_POSITION, 
			::Wx::DEFAULT_SIZE,
            tree_style
		)
		
		my_load_module_tree()
		
=begin     
		evt_tree_sel_changing(TreeTest_Ctrl) {|event| onSelChanging(event) }
        evt_tree_key_down(TreeTest_Ctrl) {|event| onTreeKeyDown(event) }
        evt_tree_item_activated(TreeTest_Ctrl) {|event| onItemActivated(event) }
        evt_right_dclick {|event| RMouseDClick(event) }		
        evt_tree_begin_drag(TreeTest_Ctrl) {|event| onBeginDrag(event) }
        evt_tree_begin_rdrag(TreeTest_Ctrl) {|event| onBeginRDrag(event) }
        evt_tree_end_drag(TreeTest_Ctrl) {|event| onEndDrag(event) }
        evt_tree_begin_label_edit(TreeTest_Ctrl) {|event| onBeginLabelEdit(event) }
        evt_tree_end_label_edit(TreeTest_Ctrl) {|event| onEndLabelEdit(event) }
        evt_tree_delete_item(TreeTest_Ctrl) {|event| onDeleteItem(event) }
        evt_tree_set_info(TreeTest_Ctrl) {|event| onSetInfo(event) }
        evt_tree_item_expanded(TreeTest_Ctrl) {|event| onItemExpanded(event) }
        evt_tree_item_expanding(TreeTest_Ctrl) {|event| onItemExpanding(event) }
        evt_tree_item_collapsed(TreeTest_Ctrl) {|event| onItemCollapsed(event) }
        evt_tree_item_collapsing(TreeTest_Ctrl) {|event| onItemCollapsing(event) }
        evt_tree_item_right_click(TreeTest_Ctrl) {|event| onItemRightClick(event) }
        evt_right_up {|event| onRMouseUp(event) }
=end
		
        evt_tree_sel_changed(FRAME_TREE_MODULES) {|event| on_sel_changed(event) }			
	end

	def on_sel_changed(event)
		if (@m_tree_modules_items.has_key?(event.get_item))
			p @m_tree_modules_items[ event.get_item ].new.description
		end
		event.skip
	end
	
	def my_load_module_tree
		@m_tree_modules_items = {}
		
		my_load_module_tree_images()

		n_root       = @m_tree_modules.get_root_item()
		n_modules    = @m_tree_modules.append_item(n_root, 'Modules', FRAME_ICONS_MODULES)
		
		n_exploits   = @m_tree_modules.append_item(n_modules, 'Exploits', FRAME_ICONS_EXPLOITS)
		n_auxiliary  = @m_tree_modules.append_item(n_modules, 'Auxiliary', FRAME_ICONS_AUXILIARY)
		n_payloads   = @m_tree_modules.append_item(n_modules, 'Payloads', FRAME_ICONS_PAYLOADS)
		n_encoders   = @m_tree_modules.append_item(n_modules, 'Encoders', FRAME_ICONS_ENCODERS)
		n_nops       = @m_tree_modules.append_item(n_modules, 'Nops', FRAME_ICONS_NOPS)				

		@m_tree_modules.expand(n_modules)

		framework.exploits.sort.each do |mod, obj|
			oid = @m_tree_modules.append_item(n_exploits, obj.new.name, FRAME_ICONS_MOD_EXPLOIT)
			@m_tree_modules_items[oid] = obj
		end

		framework.auxiliary.sort.each do |mod, obj|
			oid = @m_tree_modules.append_item(n_auxiliary, obj.new.name, FRAME_ICONS_MOD_AUXILIARY)
			@m_tree_modules_items[oid] = obj
		end
		
		framework.payloads.sort.each do |mod, obj|
			oid = @m_tree_modules.append_item(n_payloads, obj.new.name, FRAME_ICONS_MOD_PAYLOAD)
			@m_tree_modules_items[oid] = obj
		end
		
		framework.encoders.sort.each do |mod, obj|
			oid = @m_tree_modules.append_item(n_encoders, obj.new.name, FRAME_ICONS_MOD_ENCODER)
			@m_tree_modules_items[oid] = obj
		end
		
		framework.nops.sort.each do |mod, obj|
			oid = @m_tree_modules.append_item(n_nops, obj.new.name,  FRAME_ICONS_MOD_NOP)
			@m_tree_modules_items[oid] = obj
		end	
	end
	
	def my_load_module_tree_images
		isize = 16
		icons = []
		
		icons[FRAME_ICONS_MODULES]    = @driver.get_icon('modules.xpm')
		icons[FRAME_ICONS_EXPLOITS]   = @driver.get_icon('exploits.xpm')
		icons[FRAME_ICONS_AUXILIARY]  = @driver.get_icon('auxiliary.xpm')			
		icons[FRAME_ICONS_PAYLOADS]   = @driver.get_icon('payloads.xpm')
		icons[FRAME_ICONS_ENCODERS]   = @driver.get_icon('encoders.xpm')
		icons[FRAME_ICONS_NOPS]       = @driver.get_icon('nops.xpm')
	
		icons[FRAME_ICONS_MOD_EXPLOIT] = @driver.get_icon('mod_exploit.xpm')
		icons[FRAME_ICONS_MOD_PAYLOAD] = @driver.get_icon('mod_payload.xpm')
 
		# Make an image list containing small icons
		images = ::Wx::ImageList.new(isize, isize, TRUE)
		   
		for i in 0 ... icons.length
			next if not icons[i]
			sizeOrig = icons[i].get_width()
			
			if isize == sizeOrig
				images.add(icons[i])
			else
				images.add(::Wx::Bitmap.new(icons[i].convert_to_image.rescale(isize, isize)))
			end
		end

		@m_tree_modules.assign_image_list(images)	
	end
	
	def resize
 		size = get_client_size()
        @m_tree_modules.set_size_xy(size.x, 2*size.y/3)		
	end	
end

end
end
end
