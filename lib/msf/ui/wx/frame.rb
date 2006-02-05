module Msf
module Ui
module Wx

class MyFrame < ::Wx::Frame

	include Msf::Ui::Wx::MyControls
	
	attr_reader :m_panel
	
	def initialize(frame, title, x, y, w, h)
		super(frame, -1, title, ::Wx::Point.new(x, y), ::Wx::Size.new(w, h))
		
		# Reduce flicker on scroll
		set_background_colour(::Wx::Colour.new(255, 255, 255))

        # Give it an icon
        set_icon(driver.get_icon('msfwx.xpm'))
		
		# Add handlers for the menu items
		evt_menu(APP_MENU_QUIT)   {on_quit}
		evt_menu(APP_MENU_ABOUT)  {on_about}
		evt_menu(APP_MENU_RELOAD) {on_reload}
		
		# Create 
		@m_panel = MyPanel.new( self, 10, 10, 300, 100 )

		my_create_module_tree()
	end
	
	def on_quit
		close(TRUE)
	end
	
	def on_about
        dialog = ::Wx::MessageDialog.new(
			self, 
			"The is the Metasploit Framework Wx Interface.\n\n",
			"About the Metasploit Framework", 
			::Wx::OK
		)

        dialog.show_modal()
	end
	
	def on_reload
		# XXX actually reload the modules!
		@m_tree_modules_exploits.delete_all_items
		@m_tree_modules_payloads.delete_all_items
		@m_tree_modules_sessions.delete_all_items
		@m_tree_modules_jobs.delete_all_items
		
		@m_tree_modules_items = {}
		my_load_module_tree()
	end
	
	def my_create_module_tree()
		tree_style = 
#			::Wx::TR_TWIST_BUTTONS |
#			::Wx::TR_HAS_BUTTONS |		
			::Wx::TR_HIDE_ROOT |
			::Wx::TR_NO_LINES |
			::Wx::TR_FULL_ROW_HIGHLIGHT |
			::Wx::TR_DEFAULT_STYLE 			

		@m_tree_modules_exploits = Msf::Ui::Wx::MyControls::MyModuleTree.new(
			@m_panel.m_panel_exploits,
			FRAME_TREE_MODULES_EXPLOITS,
			::Wx::DEFAULT_POSITION, 
			::Wx::DEFAULT_SIZE,
            tree_style
		)

		@m_tree_modules_payloads = Msf::Ui::Wx::MyControls::MyModuleTree.new(
			@m_panel.m_panel_payloads,
			FRAME_TREE_MODULES_PAYLOADS,
			::Wx::DEFAULT_POSITION, 
			::Wx::DEFAULT_SIZE,
            tree_style
		)

		@m_tree_modules_sessions = Msf::Ui::Wx::MyControls::MyModuleTree.new(
			@m_panel.m_panel_sessions,
			FRAME_TREE_MODULES_SESSIONS,
			::Wx::DEFAULT_POSITION, 
			::Wx::DEFAULT_SIZE,
            tree_style
		)
		
		@m_tree_modules_jobs = Msf::Ui::Wx::MyControls::MyModuleTree.new(
			@m_panel.m_panel_jobs,
			FRAME_TREE_MODULES_JOBS,
			::Wx::DEFAULT_POSITION, 
			::Wx::DEFAULT_SIZE,
            tree_style
		)
								
		c = ::Wx::LayoutConstraints.new
		c.top.same_as( @m_panel.m_panel_exploits, ::Wx::LAYOUT_TOP, 2 )
		c.height.percent_of( @m_panel.m_panel_exploits, ::Wx::LAYOUT_BOTTOM, 95 )
		c.left.same_as( @m_panel.m_panel_exploits, ::Wx::LAYOUT_LEFT, 2 )
		c.width.percent_of( @m_panel.m_panel_exploits, ::Wx::LAYOUT_WIDTH, 99 )
		@m_tree_modules_exploits.set_constraints(c)

		c = ::Wx::LayoutConstraints.new
		c.top.same_as( @m_panel.m_panel_payloads, ::Wx::LAYOUT_TOP, 2 )
		c.height.percent_of( @m_panel.m_panel_payloads, ::Wx::LAYOUT_BOTTOM, 95 )
		c.left.same_as( @m_panel.m_panel_payloads, ::Wx::LAYOUT_LEFT, 2 )
		c.width.percent_of( @m_panel.m_panel_payloads, ::Wx::LAYOUT_WIDTH, 99 )
		@m_tree_modules_payloads.set_constraints(c)

		c = ::Wx::LayoutConstraints.new
		c.top.same_as( @m_panel.m_panel_sessions, ::Wx::LAYOUT_TOP, 2 )
		c.height.percent_of( @m_panel.m_panel_sessions, ::Wx::LAYOUT_BOTTOM, 95 )
		c.left.same_as( @m_panel.m_panel_sessions, ::Wx::LAYOUT_LEFT, 2 )
		c.width.percent_of( @m_panel.m_panel_sessions, ::Wx::LAYOUT_WIDTH, 99 )
		@m_tree_modules_sessions.set_constraints(c)
		
		c = ::Wx::LayoutConstraints.new
		c.top.same_as( @m_panel.m_panel_jobs, ::Wx::LAYOUT_TOP, 2 )
		c.height.percent_of( @m_panel.m_panel_jobs, ::Wx::LAYOUT_BOTTOM, 95 )
		c.left.same_as( @m_panel.m_panel_jobs, ::Wx::LAYOUT_LEFT, 2 )
		c.width.percent_of( @m_panel.m_panel_jobs, ::Wx::LAYOUT_WIDTH, 99 )
		@m_tree_modules_jobs.set_constraints(c)
								
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
		
        evt_tree_sel_changed(FRAME_TREE_MODULES_EXPLOITS) {|event| on_sel_changed_exploits(event) }			
        evt_tree_sel_changed(FRAME_TREE_MODULES_PAYLOADS) {|event| on_sel_changed_payloads(event) }			
        evt_tree_sel_changed(FRAME_TREE_MODULES_SESSIONS) {|event| on_sel_changed_sessions(event) }			
        evt_tree_sel_changed(FRAME_TREE_MODULES_JOBS) {|event| on_sel_changed_jobs(event) }
								
	end

	def on_sel_changed_exploits(event)
		if (@m_tree_modules_items.has_key?(event.get_item))
			@m_panel.on_module_select(@m_tree_modules_items[ event.get_item ])
		end
		event.skip
	end

	def on_sel_changed_payloads(event)
		if (@m_tree_modules_items.has_key?(event.get_item))
			@m_panel.on_module_select(@m_tree_modules_items[ event.get_item ])
		end
		event.skip
	end
	
	def on_dclick_exploits(event)
		if (@m_tree_modules_items.has_key?(event.get_item))
			@m_panel.on_module_dclick(@m_tree_modules_items[ event.get_item ])
		end
		event.skip
	end

	def on_dclick_payloads(event)
		if (@m_tree_modules_items.has_key?(event.get_item))
			@m_panel.on_module_dclick(@m_tree_modules_items[ event.get_item ])
		end
		event.skip
	end
		
	def on_sel_changed_sessions(event)
		event.skip
	end
	
	def on_sel_changed_jobs(event)
		event.skip
	end
				
	def my_load_module_tree(filter=/.*/)
	
		::Wx::BusyCursor.busy do |x|
			@m_tree_modules_items = {}

			my_load_module_tree_images()

			# Load the exploit modules
			n_root       = @m_tree_modules_exploits.get_root_item()
			n_modules    = @m_tree_modules_exploits.append_item(n_root, 'Exploits', FRAME_ICONS_MODULES)			
			n_exploits   = @m_tree_modules_exploits.append_item(n_modules, 'Standard', FRAME_ICONS_EXPLOITS)
			n_auxiliary  = @m_tree_modules_exploits.append_item(n_modules, 'Auxiliary', FRAME_ICONS_AUXILIARY)

			framework.exploits.sort.each do |mod, obj|
				next if not mod.match(filter)
				oid = @m_tree_modules_exploits.append_item(n_exploits, obj.new.name, FRAME_ICONS_MOD_EXPLOIT)
				@m_tree_modules_items[oid] = obj
			end

			framework.auxiliary.sort.each do |mod, obj|
				next if not mod.match(filter)
				oid = @m_tree_modules_exploits.append_item(n_auxiliary, obj.new.name, FRAME_ICONS_MOD_AUXILIARY)
				@m_tree_modules_items[oid] = obj
			end
			
			@m_tree_modules_exploits.expand(n_modules)


			# Load the non-exploit modules
			n_root       = @m_tree_modules_payloads.get_root_item()
			n_modules    = @m_tree_modules_payloads.append_item(n_root, 'Modules', FRAME_ICONS_MODULES)			
			n_payloads   = @m_tree_modules_payloads.append_item(n_modules, 'Payloads', FRAME_ICONS_PAYLOADS)
			n_encoders   = @m_tree_modules_payloads.append_item(n_modules, 'Encoders', FRAME_ICONS_ENCODERS)
			n_nops       = @m_tree_modules_payloads.append_item(n_modules, 'Nops', FRAME_ICONS_NOPS)
			
			
			framework.payloads.sort.each do |mod, obj|
				next if not mod.match(filter)
				oid = @m_tree_modules_payloads.append_item(n_payloads, obj.new.name, FRAME_ICONS_MOD_PAYLOAD)
				@m_tree_modules_items[oid] = obj
			end

			framework.encoders.sort.each do |mod, obj|
				next if not mod.match(filter)			
				oid = @m_tree_modules_payloads.append_item(n_encoders, obj.new.name, FRAME_ICONS_MOD_ENCODER)
				@m_tree_modules_items[oid] = obj
			end

			framework.nops.sort.each do |mod, obj|
				next if not mod.match(filter)
				oid = @m_tree_modules_payloads.append_item(n_nops, obj.new.name,  FRAME_ICONS_MOD_NOP)
				@m_tree_modules_items[oid] = obj
			end
			
			@m_tree_modules_exploits.expand(n_modules)
			
			# Load the sessions list
			n_root       = @m_tree_modules_sessions.get_root_item()
			n_sessions   = @m_tree_modules_sessions.append_item(n_root, 'Sessions', FRAME_ICONS_MODULES)
			n_shells     = @m_tree_modules_sessions.append_item(n_sessions, 'Shell Sessions', FRAME_ICONS_EXPLOITS)
			@m_tree_modules_sessions.expand(n_sessions)

			# Load the jobs list
			n_root       = @m_tree_modules_jobs.get_root_item()
			n_jobs       = @m_tree_modules_jobs.append_item(n_root, 'Jobs', FRAME_ICONS_MODULES)
			n_passive    = @m_tree_modules_jobs.append_item(n_jobs, 'Passive Exploits', FRAME_ICONS_EXPLOITS)
			n_auxiliary  = @m_tree_modules_jobs.append_item(n_jobs, 'Auxiliary Modules', FRAME_ICONS_AUXILIARY)
			@m_tree_modules_jobs.expand(n_jobs)
		end

	end
	
	def my_load_module_tree_images
		isize = 16
		icons = []
		
		icons[FRAME_ICONS_MODULES]    = driver.get_icon('modules.xpm')
		icons[FRAME_ICONS_EXPLOITS]   = driver.get_icon('exploits.xpm')
		icons[FRAME_ICONS_AUXILIARY]  = driver.get_icon('auxiliary.xpm')			
		icons[FRAME_ICONS_PAYLOADS]   = driver.get_icon('payloads.xpm')
		icons[FRAME_ICONS_ENCODERS]   = driver.get_icon('encoders.xpm')
		icons[FRAME_ICONS_NOPS]       = driver.get_icon('nops.xpm')
	
		icons[FRAME_ICONS_MOD_EXPLOIT] = driver.get_icon('mod_exploit.xpm')
		icons[FRAME_ICONS_MOD_PAYLOAD] = driver.get_icon('mod_payload.xpm')
 
 		# XXXX We need a unique ImageList for every TreeView or we SEGV on cleanup!!!
		# Make an image list containing small icons
		exploit_images = ::Wx::ImageList.new(isize, isize, TRUE)
		payload_images = ::Wx::ImageList.new(isize, isize, TRUE)
		session_images = ::Wx::ImageList.new(isize, isize, TRUE)
		job_images = ::Wx::ImageList.new(isize, isize, TRUE)
		
		for i in 0 ... icons.length
			next if not icons[i]
			sizeOrig = icons[i].get_width()
			
			if isize == sizeOrig
				exploit_images.add(icons[i])
				payload_images.add(icons[i])
				session_images.add(icons[i])
				job_images.add(icons[i])
			else
				exploit_images.add(::Wx::Bitmap.new(icons[i].convert_to_image.rescale(isize, isize)))
				payload_images.add(::Wx::Bitmap.new(icons[i].convert_to_image.rescale(isize, isize)))
				session_images.add(::Wx::Bitmap.new(icons[i].convert_to_image.rescale(isize, isize)))
				job_images.add(::Wx::Bitmap.new(icons[i].convert_to_image.rescale(isize, isize)))				
			end
		end

		@m_tree_modules_exploits.assign_image_list(exploit_images)
		@m_tree_modules_payloads.assign_image_list(payload_images)
		@m_tree_modules_sessions.assign_image_list(session_images)
		@m_tree_modules_jobs.assign_image_list(job_images)
	end
	
	def resize
 		size = get_client_size()
        @m_tree_modules_exploits.set_size_xy(size.x, 2*size.y/3)
		@m_tree_modules_payloads.set_size_xy(size.x, 2*size.y/3)
		@m_tree_modules_sessions.set_size_xy(size.x, 2*size.y/3)
		@m_tree_modules_jobs.set_size_xy(size.x, 2*size.y/3)	
	end	
end

end
end
end
