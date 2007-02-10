module Msf
module Ui
module Gtk2

##
# This class describe the modules treeview
##
class MyModuleTree < MyGlade
	CATEGORY, MODULE, ADV, APP = *(0..4).to_a
	
	include Msf::Ui::Gtk2::MyControls
	
	def initialize(treeview, viewmodule, tree_rhost, treesession)
		super('menu_module')
		
		@treeview1 = treeview
		@treeview1.enable_search = true
		@tree_rhost = tree_rhost
		@session_tree = treesession
		
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
				elsif (event.event_type == Gdk::Event::BUTTON2_PRESS)
					path, column, x, y = treeview.get_path_at_pos(event.x, event.y)
					begin
						iter = @treeview1.model.get_iter(path)
						if (iter.get_value(ADV) == false)
							if (iter.get_value(APP) == "Standard")
								treeview.selection.select_path(path)
								active(iter)
								MsfAssistant.new(@session_tree, iter.get_value(1))
							end							
						end
					rescue
						nil
					end
				end
			end
		end
		
		@one_shot.signal_connect('activate') do |item|
			if active_module = @selection.selected
				MsfAssistant.new(@session_tree, active_module.get_value(MODULE))
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
		iter.set_value(MODULE, nil)
		iter.set_value(ADV, true)
	
		# Add Exploits childs
		framework.exploits.each_module do |mod, obj|
			next if not mod.match(filter)
			child_iter = @model.append(iter)
			child_iter.set_value(CATEGORY, obj.new.name)
			child_iter.set_value(MODULE, obj.new)
			child_iter.set_value(ADV, false)
			child_iter.set_value(APP, "Standard")
		end
		
		#
		# Add Parent "Auxiliary (nbr auxiliary)"
		#
		iter = @model.append(nil)
		iter.set_value(CATEGORY, "Auxiliary (#{framework.stats.num_auxiliary.to_s})")
		iter.set_value(MODULE, nil)
		iter.set_value(ADV, true)
		
		# Add Auxiliary childs
		framework.auxiliary.each_module do |mod, obj|
		    next if not mod.match(filter)
		    child_iter = @model.append(iter)
		    child_iter.set_value(CATEGORY, obj.new.name)
		    child_iter.set_value(MODULE, obj.new)
		    child_iter.set_value(ADV, false)
		    child_iter.set_value(APP, "Auxiliary")
		end
		
		#
		# Add Parent "Payloads (nbr payloads)"
		#
		iter = @model.append(nil)
		iter.set_value(CATEGORY, "Payloads (#{framework.stats.num_payloads.to_s})")
		iter.set_value(MODULE, nil)
		iter.set_value(ADV, true)
	
		# Add Payloads childs
		framework.payloads.each_module do |mod, obj|
			next if not mod.match(filter)
			child_iter = @model.append(iter)
			child_iter.set_value(CATEGORY, obj.new.name)
			child_iter.set_value(MODULE, obj.new)
			child_iter.set_value(ADV, false)
			child_iter.set_value(APP, "Payloads")
		end
		
		#
		# Add Parent "Nops (nbr nops)"
		#
		iter = @model.append(nil)
		iter.set_value(CATEGORY, "NOPs (#{framework.stats.num_nops.to_s})")
		iter.set_value(MODULE, nil)
		iter.set_value(ADV, true)
	
		# Add nops childs
		framework.nops.each_module do |mod, obj|
			next if not mod.match(filter)
			child_iter = @model.append(iter)
			child_iter.set_value(CATEGORY, obj.new.name)
			child_iter.set_value(MODULE, obj.new)
			child_iter.set_value(ADV, false)
			child_iter.set_value(APP, "NOPs")
		end
		
		#
		# Add Parent "Encoders (nbr encoders)"
		#
		iter = @model.append(nil)
		iter.set_value(CATEGORY, "Encoders (#{framework.stats.num_encoders.to_s})")
		iter.set_value(MODULE, nil)
		iter.set_value(ADV, true)
	
		# Add Encoders childs
		framework.encoders.each_module do |mod, obj|
			next if not mod.match(filter)
			child_iter = @model.append(iter)
			child_iter.set_value(CATEGORY, obj.new.name)
			child_iter.set_value(MODULE, obj.new)
			child_iter.set_value(ADV, false)
			iter.set_value(APP, "Encoders")
		end
	end # def add_modules
  
	#
	# Display the module information
	#
	def active(iter)
		if not iter[MODULE].nil?
			@buffer.insert_module(iter.get_value(MODULE))
		end
	end
	
	def refresh
		@model.clear()
		add_modules()
	end

end # Class MyExploitsTree


class MyTargetTree < MyGlade
	PIX, RHOST, RUNNING, NAME, OBJECT = *(0..5).to_a
    
	include Msf::Ui::Gtk2::MyControls

	def initialize(treeview, session_tree)
		super('menu_target_tree')
		
		@treeview2 = treeview
		@session_tree = session_tree
		
		@model = Gtk::TreeStore.new(Gdk::Pixbuf,	# Pix rhost
						String, 	# RHOST
						Gdk::Pixbuf,	# Pix for the running state
						String, 	# exploit refname
						Object		# Exploit Object
						)
    		
		# Renderer
		renderer_pix = Gtk::CellRendererPixbuf.new
		renderer_rhost = Gtk::CellRendererText.new
		renderer_running_pix = Gtk::CellRendererPixbuf.new
		renderer_name = Gtk::CellRendererText.new
		
		# RHOST Gtk::TreeViewColumn
		column_rhost = Gtk::TreeViewColumn.new
		column_rhost.set_title("rhost")
		column_rhost.pack_start(renderer_pix, false)
		column_rhost.set_cell_data_func(renderer_pix) do |column, cell, model, iter|
			cell.pixbuf = iter[PIX]
		end
		column_rhost.pack_start(renderer_rhost, true)
		column_rhost.set_cell_data_func(renderer_rhost) do |column, cell, model, iter|
			cell.text = iter[RHOST]
		end
		column_rhost.sort_column_id = RHOST
    	
		# Running Gtk::TreeViewColumn
		column_running = Gtk::TreeViewColumn.new
		column_running.sizing = Gtk::TreeViewColumn::FIXED
		column_running.fixed_width = 20
		column_running.set_title("S")
		column_running.pack_start(renderer_running_pix, false)
		column_running.set_cell_data_func(renderer_running_pix) do |column, cell, model, iter|
			cell.pixbuf = iter[RUNNING]
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
		@treeview2.append_column(column_rhost)
		@treeview2.append_column(column_running)
		@treeview2.append_column(column_name)
		
		# Add AutoPWN
		@autopwn_iter = @model.append(nil)
		@autopwn_iter.set_value(PIX, driver.get_icon("menu_autopwn.png"))	
		@autopwn_iter.set_value(RHOST, "AutoPWN")	
		
		# Add Parent "One shot"
		@oneshot_iter = @model.append(nil)
		@oneshot_iter.set_value(PIX, driver.get_icon("menu_oneshot.png"))
		@oneshot_iter.set_value(RHOST, "One shot")
		
		# TreeView Signals
		@treeview2.signal_connect('button_press_event') do |treeview, event|
			if event.kind_of? Gdk::EventButton
				if (event.button == 3)
					path, column, x, y = treeview.get_path_at_pos(event.x, event.y)
					
					begin
						iter = @treeview2.model.get_iter(path)
						if iter.get_value(PIX).nil? && iter.get_value(RUNNING).nil?
							treeview.selection.select_path(path)
							@menu_targetree.popup(nil, nil, event.button, event.time)
						elsif not iter.get_value(RUNNING).nil?
							treeview.selection.select_path(path)
							nil
							# @menu_owned.popup(nil, nil, event.button, event.time)
						end
					rescue
						nil
					end
				end
			end
		end
		
		# Menu Signals
		@stop.signal_connect('activate') do |item|
			if current = @selection.selected
				puts "TODO: Kill exploit"
			end
		end
				
		@delete.signal_connect('activate') do |item|
			if current = @selection.selected
				remove_rhost(current)
			end
		end
	end # def initialize
    
	#
	# Add One Shot
	#
	def add_oneshot(target, exploit)
		oneshot_childiter = @model.append(@oneshot_iter)
		#oneshot_childiter.set_value(PIX, nil)
		oneshot_childiter.set_value(RHOST, target)
		oneshot_childiter.set_value(NAME, exploit.shortname)
		oneshot_childiter.set_value(OBJECT, exploit)
		@treeview2.expand_all()
	end
	
	#
	# Remove Target
	#
	def remove_rhost(iter)
		@treeview2.model.remove(iter)
	end
    
end #class MyTargetTree

class MySessionTree
	ID_SESSION, RHOST, PAYLOAD, O_SESSION, BUFFER, PIPE, INPUT, OUTPUT = *(0..8).to_a
	
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
		renderer_rhost = Gtk::CellRendererText.new
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
		column_rhost = Gtk::TreeViewColumn.new
		column_rhost.set_title("Target")
		column_rhost.pack_start(renderer_rhost, true)
		column_rhost.set_cell_data_func(renderer_rhost) do |column, cell, model, iter|
			cell.text = iter[RHOST]
		end
		column_rhost.sort_column_id = RHOST
    	
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
		@treeview.append_column(column_rhost)
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
		iter[RHOST] = options['RHOST']
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