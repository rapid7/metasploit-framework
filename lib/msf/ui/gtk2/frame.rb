module Msf
module Ui
module Gtk2

class MyExploitsTree < MyGlade
	CATEGORY, EXPLOIT, ADV, APP = *(0..4).to_a
	
	include Msf::Ui::Gtk2::MyControls
	
	def initialize(treeview, viewmodule, tree_target)
		super('menu_module')
		
		@treeview1 = treeview
		@treeview1.enable_search = true
		@tree_target = tree_target
		
		@model = Gtk::TreeStore.new(String,		# Module name
						Object,		# Exploit?
						TrueClass,	# ADV?
						String		# Appartenance
						)
		
		# Init buffer module with tags
		buff = Gtk::TextBuffer.new
		viewmodule.set_buffer(buff)
		viewmodule.set_editable(false)
		viewmodule.set_cursor_visible(false)
		@buffer = MyModuleView.new(buff)
		
		# Renderer Module
		#renderer1 = Gtk::CellRendererPixbuf.new
		renderer1 = Gtk::CellRendererText.new
		
		column1 = Gtk::TreeViewColumn.new("Modules", renderer1, 'text' => CATEGORY)
		column1.sort_column_id = CATEGORY
		
		#set model to treeview
		@treeview1.set_size_request(380, -1)
		@treeview1.set_model(@model)
		
		@treeview1.rules_hint = true
		
		@selection = @treeview1.selection
		@treeview1.selection.mode = Gtk::SELECTION_BROWSE
		
		@treeview1.append_column(column1)
		
		# Signals
		@treeview1.signal_connect('cursor-changed') do |widget, event|
			widget.selection.selected_each do |model, path, iter|
				active(iter)
			end
		end
		
		@treeview1.signal_connect('button_press_event') do |treeview, event|
			if event.kind_of? Gdk::EventButton
				if (event.button == 3)
					path, column, x, y = treeview.get_path_at_pos(event.x, event.y)
					begin
						iter = @treeview1.model.get_iter(path)
						if (iter.get_value(ADV) == false)
							if (iter.get_value(APP) == "Standard")
								treeview.selection.select_path(path)
								active(iter)
								@menu_module.popup(nil, nil, event.button, event.time)
							end
							
							# TODO: Add specific menus for :
							# - payload
							# - auxiliary
							# - nops
							# - encoders
							
						end
					rescue
						nil
					end
				end
			end
		end
		
		@one_shot.signal_connect('activate') do |item|
			if current = @selection.selected
				MyOneShot.new(@tree_target, current)
			end
		end
		
		# Add modules in the Gtk::TreeView
		add_modules()
		
	end # def initialize
    
    #
    # Add Exploits module in the treeview
    #
    	def add_modules(filter=/.*/)
		@m_tree_modules_items = {}
		
		#
		# Add Parent "Standard (nbr exploits)"
		#
		iter = @model.append(nil)
		iter.set_value(CATEGORY, "Standard (#{framework.stats.num_exploits.to_s})")
		iter.set_value(EXPLOIT, nil)
		iter.set_value(ADV, true)
	
		# Add Exploits childs
		framework.exploits.each_module do |mod, obj|
			next if not mod.match(filter)
			child_iter = @model.append(iter)
			child_iter.set_value(CATEGORY, obj.new.name)
			child_iter.set_value(EXPLOIT, obj.new)
			child_iter.set_value(ADV, false)
			child_iter.set_value(APP, "Standard")
		end
		
		#
		# Add Parent "Auxiliary (nbr auxiliary)"
		#
		iter = @model.append(nil)
		iter.set_value(CATEGORY, "Auxiliary (#{framework.stats.num_auxiliary.to_s})")
		iter.set_value(EXPLOIT, nil)
		iter.set_value(ADV, true)
		
		# Add Auxiliary childs
		framework.auxiliary.each_module do |mod, obj|
		    next if not mod.match(filter)
		    child_iter = @model.append(iter)
		    child_iter.set_value(CATEGORY, obj.new.name)
		    child_iter.set_value(EXPLOIT, obj.new)
		    child_iter.set_value(ADV, false)
		    child_iter.set_value(APP, "Auxiliary")
		end
		
		#
		# Add Parent "Payloads (nbr payloads)"
		#
		iter = @model.append(nil)
		iter.set_value(CATEGORY, "Payloads (#{framework.stats.num_payloads.to_s})")
		iter.set_value(EXPLOIT, nil)
		iter.set_value(ADV, true)
	
		# Add Payloads childs
		framework.payloads.each_module do |mod, obj|
			next if not mod.match(filter)
			child_iter = @model.append(iter)
			child_iter.set_value(CATEGORY, obj.new.name)
			child_iter.set_value(EXPLOIT, obj.new)
			child_iter.set_value(ADV, false)
			child_iter.set_value(APP, "Payloads")
		end
		
		#
		# Add Parent "Nops (nbr nops)"
		#
		iter = @model.append(nil)
		iter.set_value(CATEGORY, "NOPs (#{framework.stats.num_nops.to_s})")
		iter.set_value(EXPLOIT, nil)
		iter.set_value(ADV, true)
	
		# Add nops childs
		framework.nops.each_module do |mod, obj|
			next if not mod.match(filter)
			child_iter = @model.append(iter)
			child_iter.set_value(CATEGORY, obj.new.name)
			child_iter.set_value(EXPLOIT, obj.new)
			child_iter.set_value(ADV, false)
			child_iter.set_value(APP, "NOPs")
		end
		
		#
		# Add Parent "Encoders (nbr encoders)"
		#
		iter = @model.append(nil)
		iter.set_value(CATEGORY, "Encoders (#{framework.stats.num_encoders.to_s})")
		iter.set_value(EXPLOIT, nil)
		iter.set_value(ADV, true)
	
		# Add Encoders childs
		framework.encoders.each_module do |mod, obj|
			next if not mod.match(filter)
			child_iter = @model.append(iter)
			child_iter.set_value(CATEGORY, obj.new.name)
			child_iter.set_value(EXPLOIT, obj.new)
			child_iter.set_value(ADV, false)
			iter.set_value(APP, "Encoders")
		end
	end # def add_modules
  
	#
	# Display the module information
	#
	def active(iter)
		if not iter[EXPLOIT].nil?
			@buffer.insert_module(iter.get_value(EXPLOIT))
		end
	end
	
	def refresh
		@model.clear()
		add_modules()
	end

end # Class MyExploitsTree


class MyTargetTree < MyGlade
	PIX, TARGET, STAGED, OWNED, NAME, OBJECT, DRIVER , INPUT, OUTPUT= *(0..9).to_a
    
	include Msf::Ui::Gtk2::MyControls

	def initialize(treeview, session_tree)
		super('menu_staged')
		
		@treeview2 = treeview
		@session_tree = session_tree
		
		@model = Gtk::TreeStore.new(Gdk::Pixbuf,	# Pix
						String, 	# RHOST
						Gdk::Pixbuf,	# Pix Staged
						Gdk::Pixbuf,	# Pix Owned
						String, 	# exploit refname
						Object,		# ?
						Object,		# Msf::ExploitDriver
						Object,	 	# INPUT
						Object 		# OUTPUT
						)
    		
		# Renderer
		renderer_pix = Gtk::CellRendererPixbuf.new
		renderer_target = Gtk::CellRendererText.new
		renderer_staged_pix = Gtk::CellRendererPixbuf.new
		renderer_owned_pix = Gtk::CellRendererPixbuf.new
		renderer_name = Gtk::CellRendererText.new
		
		# Target Gtk::TreeViewColumn
		column_target = Gtk::TreeViewColumn.new
		column_target.set_title("Target")
		column_target.pack_start(renderer_pix, false)
		column_target.set_cell_data_func(renderer_pix) do |column, cell, model, iter|
			cell.pixbuf = iter[PIX]
		end
		column_target.pack_start(renderer_target, true)
		column_target.set_cell_data_func(renderer_target) do |column, cell, model, iter|
			cell.text = iter[TARGET]
		end
		column_target.sort_column_id = TARGET
    	
		# Staged Gtk::TreeViewColumn
		column_staged = Gtk::TreeViewColumn.new
		column_staged.sizing = Gtk::TreeViewColumn::FIXED
		column_staged.fixed_width = 20
		column_staged.set_title("S")
		column_staged.pack_start(renderer_staged_pix, false)
		column_staged.set_cell_data_func(renderer_staged_pix) do |column, cell, model, iter|
			cell.pixbuf = iter[STAGED]
		end
    	
		# Owned Gtk::TreeViewColumn
		column_owned = Gtk::TreeViewColumn.new
		column_owned.sizing = Gtk::TreeViewColumn::FIXED
		column_owned.fixed_width = 20
		#column_owned.set_fixed_width(5)
		column_owned.set_title("O")
		column_owned.pack_start(renderer_staged_pix, false)
		column_owned.set_cell_data_func(renderer_staged_pix) do |column, cell, model, iter|
			cell.pixbuf = iter[OWNED]
		end
		
		# Name Gtk::TreeViewColumn
		column_name = Gtk::TreeViewColumn.new
		column_name.set_title("Name")
		column_name.pack_start(renderer_name, true)
		column_name.set_cell_data_func(renderer_name) do |column, cell, model, iter|
			cell.text = iter[NAME]
		end
    	
		#set model to treeview
		@treeview2.set_model(@model)
		
		@selection = @treeview2.selection
		@treeview2.selection.mode = Gtk::SELECTION_BROWSE
		@treeview2.rules_hint = true
		
		# Add Gtk::TreeViewColumn
		@treeview2.append_column(column_target)
		@treeview2.append_column(column_staged)
		@treeview2.append_column(column_owned)
		@treeview2.append_column(column_name)
		
		# Add AutoPWN
		@autopwn_iter = @model.append(nil)
		@autopwn_iter.set_value(PIX, driver.get_icon("menu_autopwn.png"))	
		@autopwn_iter.set_value(TARGET, "AutoPWN")	
		
		# Add Parent "One shot"
		@oneshot_iter = @model.append(nil)
		@oneshot_iter.set_value(PIX, driver.get_icon("menu_oneshot.png"))
		@oneshot_iter.set_value(TARGET, "One shot")
		
		# Owned Gtk::Menu
		@menu_owned = Gtk::Menu.new
		
		owned_item_exploit = Gtk::ImageMenuItem.new("Exploit")
		owned_image_exploit = Gtk::Image.new
		owned_image_exploit.set(Gtk::Stock::EXECUTE, Gtk::IconSize::MENU)
		owned_item_exploit.set_image(owned_image_exploit)
		@menu_owned.append(owned_item_exploit)
		
		separator1 = Gtk::SeparatorMenuItem.new
		@menu_owned.append(separator1)
		
		owned_item_new_staged = Gtk::ImageMenuItem.new("New Staged")
		owned_image_new_staged = Gtk::Image.new
		owned_image_new_staged.set(Gtk::Stock::CONNECT, Gtk::IconSize::MENU)
		owned_item_new_staged.set_image(owned_image_new_staged)
		@menu_owned.append(owned_item_new_staged)
		
		separator2 = Gtk::SeparatorMenuItem.new
		@menu_owned.append(separator2)
		
		owned_item_delete = Gtk::ImageMenuItem.new("Delete")
		owned_image_delete = Gtk::Image.new
		owned_image_delete.set(Gtk::Stock::CLEAR, Gtk::IconSize::MENU)
		owned_item_delete.set_image(owned_image_delete)
		@menu_owned.append(owned_item_delete)
		
		@menu_owned.show_all
		
		# TreeView Signals
		@treeview2.signal_connect('button_press_event') do |treeview, event|
			if event.kind_of? Gdk::EventButton
				if (event.button == 3)
					path, column, x, y = treeview.get_path_at_pos(event.x, event.y)
					
					begin
						iter = @treeview2.model.get_iter(path)
						if iter.get_value(PIX).nil? && iter.get_value(STAGED).nil?
							treeview.selection.select_path(path)
							@menu_staged.popup(nil, nil, event.button, event.time)
						elsif not iter.get_value(STAGED).nil?
							treeview.selection.select_path(path)
							@menu_owned.popup(nil, nil, event.button, event.time)
						end
					rescue
						nil
					end
				end
			end
		end
		
		# Menu Signals
		@staged.signal_connect('activate') do |item|
			if current = @selection.selected
				add_staged(current)
			end
		end
				
		@delete.signal_connect('activate') do |item|
			if current = @selection.selected
				remove_target(current)
			end
		end

		owned_item_exploit.signal_connect('activate') do |item|
			if current = @selection.selected
				session = current[DRIVER].run
				if (session)
					current[OUTPUT].print_status("Session #{session.sid} created, interacting ...")
					current[OUTPUT].print_line
				end
			end
		end
		owned_item_delete.signal_connect('activate') do |item|
			if current = @selection.selected
				remove_target(current)
			end
		end
	end # def initialize
    
	#
	# Add One Shot
	#
	def add_oneshot(target, exploit)
		oneshot_childiter = @model.append(@oneshot_iter)
		#oneshot_childiter.set_value(PIX, nil)
		oneshot_childiter.set_value(TARGET, target)
		oneshot_childiter.set_value(NAME, exploit.shortname)
		oneshot_childiter.set_value(OBJECT, exploit)
		@treeview2.expand_all()
	end
    
	#
	# Add Staged by launching wizard (MsfAssistant
	#	
	def add_staged(staged_iter)
		MsfAssistant.new(staged_iter, @session_tree)
	end

	#
	# Remove Target
	#
	def remove_target(iter)
		@treeview2.model.remove(iter)
	end
    
end #class MyTargetTree

class MySessionTree
	ID_SESSION, TARGET, PAYLOAD, O_SESSION, BUFFER, PIPE, INPUT, OUTPUT = *(0..8).to_a
	
	def initialize(treeview)
		@treeview = treeview
		@model = Gtk::ListStore.new(String,		# Session ID
						String,		# IP Address
						String,		# Payload Type
						Object,		# Session Object
						Object,		# Gtk::TextBuffer Object
						Object,		# Bidirectional_pipe
						Object,		# Input Object
						Object		# Output Object
						)
    		
		# Renderer
		renderer_id = Gtk::CellRendererText.new
		renderer_target = Gtk::CellRendererText.new
		renderer_payload = Gtk::CellRendererText.new

		# ID Session Gtk::TreeViewColumn
		column_id = Gtk::TreeViewColumn.new
		column_id.sizing = Gtk::TreeViewColumn::FIXED
		column_id.fixed_width = 20
		column_id.set_title("ID")
		column_id.pack_start(renderer_id, true)
		column_id.set_cell_data_func(renderer_id) do |column, cell, model, iter|
			cell.text = iter[ID_SESSION]
		end
		column_id.sort_column_id = ID_SESSION
		
		# Target Gtk::TreeViewColumn
		column_target = Gtk::TreeViewColumn.new
		column_target.set_title("Target")
		column_target.pack_start(renderer_target, true)
		column_target.set_cell_data_func(renderer_target) do |column, cell, model, iter|
			cell.text = iter[TARGET]
		end
		column_target.sort_column_id = TARGET
    	
		# Payload type Gtk::TreeViewColumn
		column_payload = Gtk::TreeViewColumn.new
		column_payload.set_title("Payload")
		column_payload.pack_start(renderer_payload, true)
		column_payload.set_cell_data_func(renderer_payload) do |column, cell, model, iter|
			cell.text = iter[PAYLOAD]
		end
		column_payload.sort_column_id = PAYLOAD
    	
		#set model to treeview
		@treeview.set_model(@model)
		
		@selection = @treeview.selection
		@treeview.selection.mode = Gtk::SELECTION_BROWSE
		@treeview.rules_hint = true
		
		# Add Gtk::TreeViewColumn
		@treeview.append_column(column_id)
		@treeview.append_column(column_target)
		@treeview.append_column(column_payload)
		
		# Session Gtk::Menu
		@menu_session = Gtk::Menu.new
		
		session_item_shell = Gtk::ImageMenuItem.new("Bind Shell")
		session_image_shell = Gtk::Image.new
		session_image_shell.set(Gtk::Stock::EXECUTE, Gtk::IconSize::MENU)
		session_item_shell.set_image(session_image_shell)
		@menu_session.append(session_item_shell)
		
		separator1 = Gtk::SeparatorMenuItem.new
		@menu_session.append(separator1)
		
		@menu_session.show_all
		
		# TreeView signals
		@treeview.signal_connect('button_press_event') do |treeview, event|
			if event.kind_of? Gdk::EventButton
				if (event.button == 3)
					path, column, x, y = treeview.get_path_at_pos(event.x, event.y)
				
					begin
						iter = @treeview.model.get_iter(path)
						treeview.selection.select_path(path)
						@menu_session.popup(nil, nil, event.button, event.time)
					rescue
						nil
					end
				end
			end
		end
		
		# Items session signals
		session_item_shell.signal_connect('activate') do |item|
			if current = @selection.selected
				Msf::Ui::Gtk2::Stream::Console.new(current[O_SESSION],
									current[BUFFER],
									current[PIPE],
									current[INPUT],
									current[OUTPUT]
									)
			end
		end
		
	end # def initialize
	
	def add_session(session, options, buffer, pipe, input, output)
		iter = @model.append
		iter[ID_SESSION] = session.sid.to_s
		iter[TARGET] = options['RHOST']
		iter[PAYLOAD] = options['PAYLOAD']
		iter[O_SESSION] = session
		iter[BUFFER] = buffer
		iter[PIPE] = pipe
		iter[INPUT] = input
		iter[OUTPUT] = output		
	end
end # class MySessionTree

end
end
end