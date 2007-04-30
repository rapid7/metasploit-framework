module Msf
module Ui
module Gtk2

##
# This class describe the modules treeview
##
class MyModuleTree < MyGlade
	
	@@completion = []
	
	PIX, CATEGORY, MODULE, ADV, APP = *(0..5).to_a
	
	include Msf::Ui::Gtk2::MyControls
	
	def initialize(treeview, viewmodule)
		super('menu_module')
		
		@treeview1 = treeview
		@treeview1.enable_search = true
		
		@model = Gtk::TreeStore.new(	Gdk::Pixbuf,	# pixbuf
						String,		# Module name
						Object,		# Exploit?
						TrueClass,	# ADV?
						String		# Appartenance
						)
		# Register the model for later use
		$gtk2driver.module_model = @model
		
		# Init buffer module with tags
		buff = Gtk::TextBuffer.new
		viewmodule.set_buffer(buff)
		viewmodule.set_editable(false)
		viewmodule.set_cursor_visible(false)
		@buffer = MyModuleView.new(buff)
		
		# Renderer Module
		renderer_pix = Gtk::CellRendererPixbuf.new
		renderer_module = Gtk::CellRendererText.new
		
		column_module = Gtk::TreeViewColumn.new		
		column_module.pack_start(renderer_pix, false)
		column_module.set_cell_data_func(renderer_pix) do |column, cell, model, iter|
			cell.pixbuf = iter[PIX]
		end
		column_module.pack_start(renderer_module, true)
		column_module.set_cell_data_func(renderer_module) do |column, cell, model, iter|
			cell.text = iter[CATEGORY]
		end
		
		#set model to treeview
		@treeview1.set_size_request(380, -1)
		@treeview1.set_model(@model)
		
		@treeview1.rules_hint = true
		
		@selection = @treeview1.selection
		@treeview1.selection.mode = Gtk::SELECTION_BROWSE
		
		@treeview1.append_column(column_module)
		
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
							treeview.selection.select_path(path)
							active(iter)
							@menu_module.popup(nil, nil, event.button, event.time)
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
								MsfAssistant::Standard.new(iter.get_value(1))
							elsif (iter.get_value(APP) == "Payloads")
								treeview.selection.select_path(path)
								active(iter)
								MsfAssistant::Payload.new(iter.get_value(1))
							else
								treeview.selection.select_path(path)
								active(iter)
								MsfDialog::Error.new($gtk2driver.main, "Not available")
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
				type = active_module.get_value(APP)
				if (type == "Standard")
					MsfAssistant::Standard.new(active_module.get_value(MODULE))
				elsif (type ==  "Payloads")
					MsfAssistant::Payload.new(active_module.get_value(MODULE))
				else
					MsfDialog::Error.new($gtk2driver.main, "Not available")
				end
			end
		end
		
		# Add modules in the Gtk::TreeView
		add_modules()
		
		# Configure the module completion handles for easy reference
		$gtk2driver.module_completion = @@completion
		
	end # def initialize
    
    #
    # Add Exploits module in the treeview
    #
    def add_modules(filter=/.*/)
		
		# Add Parent "Standard (nbr exploits)"
		iter = @model.append(nil)
		iter.set_value(PIX, driver.get_icon("bug.png"))
		iter.set_value(CATEGORY, "Exploits (#{framework.stats.num_exploits.to_s})")
		iter.set_value(MODULE, nil)
		iter.set_value(ADV, true)
	
		# Add Exploits childs
		framework.exploits.each_module do |mod, obj|
			next if not mod.match(filter)
			t_module = obj.new.name
			child_iter = @model.append(iter)
			child_iter.set_value(CATEGORY, t_module)
			child_iter.set_value(MODULE, obj.new)
			child_iter.set_value(ADV, false)
			child_iter.set_value(APP, "Standard")
			@@completion.push(t_module)
		end
		
		# Add Parent "Auxiliary (nbr auxiliary)"
		iter = @model.append(nil)
		iter.set_value(PIX, driver.get_icon("zoom.png"))
		iter.set_value(CATEGORY, "Auxiliary (#{framework.stats.num_auxiliary.to_s})")
		iter.set_value(MODULE, nil)
		iter.set_value(ADV, true)
		
		# Add Auxiliary childs
		framework.auxiliary.each_module do |mod, obj|
		    next if not mod.match(filter)
		    t_module = obj.new.name
		    child_iter = @model.append(iter)
		    child_iter.set_value(CATEGORY, t_module)
		    child_iter.set_value(MODULE, obj.new)
		    child_iter.set_value(ADV, false)
		    child_iter.set_value(APP, "Auxiliary")
		    @@completion.push(t_module)
		end
		
		# Add Parent "Payloads (nbr payloads)"
		iter = @model.append(nil)
		iter.set_value(PIX, driver.get_icon("bomb.png"))
		iter.set_value(CATEGORY, "Payloads (#{framework.stats.num_payloads.to_s})")
		iter.set_value(MODULE, nil)
		iter.set_value(ADV, true)
		
		# Add Payloads childs
		framework.payloads.each_module do |mod, obj|
			next if not mod.match(filter)
			t_module = obj.new.name
			child_iter = @model.append(iter)
			child_iter.set_value(CATEGORY, t_module)
			child_iter.set_value(MODULE, obj.new)
			child_iter.set_value(ADV, false)
			child_iter.set_value(APP, "Payloads")
			@@completion.push(t_module)
		end
		
		# Add Parent "Nops (nbr nops)"
		iter = @model.append(nil)
		iter.set_value(PIX, driver.get_icon("encoders.png"))
		iter.set_value(CATEGORY, "NOPs (#{framework.stats.num_nops.to_s})")
		iter.set_value(MODULE, nil)
		iter.set_value(ADV, true)
	
		# Add nops childs
		framework.nops.each_module do |mod, obj|
			next if not mod.match(filter)
			t_module = obj.new.name
			child_iter = @model.append(iter)
			child_iter.set_value(CATEGORY, t_module)
			child_iter.set_value(MODULE, obj.new)
			child_iter.set_value(ADV, false)
			child_iter.set_value(APP, "NOPs")
			@@completion.push(t_module)
		end
		
		# Add Parent "Encoders (nbr encoders)"
		iter = @model.append(nil)
		iter.set_value(PIX, driver.get_icon("encoders.png"))
		iter.set_value(CATEGORY, "Encoders (#{framework.stats.num_encoders.to_s})")
		iter.set_value(MODULE, nil)
		iter.set_value(ADV, true)
	
		# Add Encoders childs
		framework.encoders.each_module do |mod, obj|
			next if not mod.match(filter)
			t_module = obj.new.name
			child_iter = @model.append(iter)
			child_iter.set_value(CATEGORY, t_module)
			child_iter.set_value(MODULE, obj.new)
			child_iter.set_value(ADV, false)
			iter.set_value(APP, "Encoders")
			@@completion.push(t_module)
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
	
	#
	# Refresh the module treeview with all msf modules
	#
	def refresh
		@model.clear()
		add_modules()
	end
	
	#
	# remove all iters in array_iter
	#
	def remove(iter_array)
		
		# first loop to remove unmatched iter
		iter_array.each do |iter|
			if (iter[ADV] == false)
				@model.remove(iter)
			end
		end
		
		# second loop to update parent iter with child iter
		no_child = []
		@model.each do |model, path, iter|
			if (iter[ADV] == true)
				no_child.push(iter) if not iter.has_child?
				iter[CATEGORY] = iter[CATEGORY].sub(/[0-9]+/, iter.n_children.to_s)
			end
		end
		
		# remove iter
		no_child.each do |iter|
			@model.remove(iter)
		end
	end
	
	#
	# expand the treeview
	#
	def expand
		@treeview1.expand_all
	end

end # Class MyExploitsTree


class MyJobTree < MyGlade
	PIX, TIME, NAME, OBJECT, RHOST, REFNAME = *(0..6).to_a
    
	include Msf::Ui::Gtk2::MyControls

	def initialize(treeview)		
		@treeview2 = treeview
		
		@model = Gtk::TreeStore.new(Gdk::Pixbuf,	# Pix rhost
						String, 	# process TIME
						String, 	# exploit shortname
						Object,		# Exploit Object
						String,	 	# Remote host
						String	 	# exploit refname
						)
    		
		# Renderer
		renderer_pix = Gtk::CellRendererPixbuf.new
		renderer_time = Gtk::CellRendererText.new
		renderer_name = Gtk::CellRendererText.new
		
		# Time Gtk::TreeViewColumn
		column_time = Gtk::TreeViewColumn.new
		#column_time.set_title("rhost")
		column_time.pack_start(renderer_pix, false)
		column_time.set_cell_data_func(renderer_pix) do |column, cell, model, iter|
			cell.pixbuf = iter[PIX]
		end
		column_time.pack_start(renderer_time, true)
		column_time.set_cell_data_func(renderer_time) do |column, cell, model, iter|
			cell.text = iter[TIME]
		end
		column_time.sort_column_id = TIME
		
		# Name Gtk::TreeViewColumn
		column_name = Gtk::TreeViewColumn.new
		column_name.set_title("Module")
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
		@treeview2.append_column(column_time)
		@treeview2.append_column(column_name)
		
		# Add AutoPWN
		@autopwn_iter = @model.append(nil)
		@autopwn_iter.set_value(PIX, driver.get_icon("menu_autopwn.png"))	
		@autopwn_iter.set_value(TIME, "AutoPWN")	
		
		# Add Parent "One shot"
		@oneshot_iter = @model.append(nil)
		@oneshot_iter.set_value(PIX, driver.get_icon("menu_oneshot.png"))
		@oneshot_iter.set_value(TIME, "One shot")
		
		# Job Gtk::Menu
		@menu_job = Gtk::Menu.new
		
		# Stop job
		kill_job_item_shell = Gtk::ImageMenuItem.new("Kill Job")
		kill_job_image_shell = Gtk::Image.new
		kill_job_image_shell.set(Gtk::Stock::CLOSE, Gtk::IconSize::MENU)
		kill_job_item_shell.set_image(kill_job_image_shell)
		@menu_job.append(kill_job_item_shell)		
		
		# Refresh
		refresh_job_item_shell = Gtk::ImageMenuItem.new("Refresh")
		refresh_job_image_shell = Gtk::Image.new
		refresh_job_image_shell.set(Gtk::Stock::REFRESH, Gtk::IconSize::MENU)
		refresh_job_item_shell.set_image(refresh_job_image_shell)
		@menu_job.append(refresh_job_item_shell)

		@menu_job.show_all
		
		# TreeView Signals
		@treeview2.signal_connect('button_press_event') do |treeview, event|
			if event.kind_of? Gdk::EventButton
				if (event.button == 3)
					path, column, x, y = treeview.get_path_at_pos(event.x, event.y)
					
					begin
						iter = @treeview2.model.get_iter(path)
						treeview.selection.select_path(path)
						@menu_job.popup(nil, nil, event.button, event.time)
					rescue
						nil
						#@menu_job.popup(nil, nil, event.button, event.time)
					end
				end
			end
		end
		
		# Menu Signals
		kill_job_item_shell.signal_connect('activate') do |item|
			if current = @selection.selected
				stop_job(current)
			end
		end

		refresh_job_item_shell.signal_connect('activate') do |item|
			refresh_job()
		end
		
	end # def initialize
    
	#
	# Add One Shot
	#
	def add_oneshot(exploit, rhost)
		time = Time.now
		oneshot_childiter = @model.append(@oneshot_iter)
		#oneshot_childiter.set_value(PIX, nil)
		oneshot_childiter.set_value(TIME, Time.now.strftime("%H:%m:%S"))
		oneshot_childiter.set_value(NAME, exploit.shortname)
		oneshot_childiter.set_value(OBJECT, exploit)
		oneshot_childiter.set_value(RHOST, rhost)
		oneshot_childiter.set_value(REFNAME, exploit.refname)
		@treeview2.expand_all()
	end
	
	#
	# Stop job and remove it from the job tree
	#
	def stop_job(iter)
		framework.jobs.each_key do |i|
			if (framework.jobs[i].name.split(": ")[1] ==  iter[REFNAME])
				
				# Stopping job
				framework.jobs.stop_job(i)
				
				# Informing the user
				$gtk2driver.append_log_view("[*] Stopping exploit: #{iter[REFNAME]}")
				
				# Removing the job from the job tree
				@model.remove(iter)
			end
		end
	end
	
	#
	# Refresh job
	#
	def refresh_job
		puts "TODO: refresh the job tree =>"
		framework.jobs.keys.sort.each do |k|
			puts framework.jobs[k].name
		end		
	end
	
	#
	# Remove Target if not a passive exploit
	#
	def remove_job(rhost, name)
		found = nil
		@model.each do |model,path,iter|
			if (iter[RHOST] == rhost and iter[REFNAME] == name and iter[OBJECT].passive? == false)
				found = iter
				break
			end
		end
		
		@model.remove(found) if found
	end
    
end #class MyJobTree

class MySessionTree
	ID_SESSION, PEER, PAYLOAD, O_SESSION, O_BUFFER = *(0..5).to_a
	
	include Msf::Ui::Gtk2::MyControls
	
	def initialize(treeview)
		@treeview = treeview
		@model = Gtk::ListStore.new(String,		# Session ID
						String,		# IP Address
						String,		# Payload Type
						Object,		# Session Object
						Object		# Gtk::TextBuffer
						)
    		
		# Renderer
		renderer_id      = Gtk::CellRendererText.new
		renderer_peer    = Gtk::CellRendererText.new
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
		column_peer = Gtk::TreeViewColumn.new
		column_peer.set_title("Target")
		column_peer.pack_start(renderer_peer, true)
		column_peer.set_cell_data_func(renderer_peer) do |column, cell, model, iter|
			cell.text = iter[PEER]
		end
		#column_peer.sort_column_id = PEER
    	
		# Payload type Gtk::TreeViewColumn
		column_payload = Gtk::TreeViewColumn.new
		column_payload.set_title("Payload")
		column_payload.pack_start(renderer_payload, true)
		column_payload.set_cell_data_func(renderer_payload) do |column, cell, model, iter|
			cell.text = iter[PAYLOAD]
		end
		#column_payload.sort_column_id = PAYLOAD
    	
		#set model to treeview
		@treeview.set_model(@model)
		
		@selection = @treeview.selection
		@treeview.selection.mode = Gtk::SELECTION_BROWSE
		@treeview.rules_hint = true
		
		# Add Gtk::TreeViewColumn
		@treeview.append_column(column_id)
		@treeview.append_column(column_peer)
		@treeview.append_column(column_payload)
		
		# Session Gtk::Menu
		@menu_session = Gtk::Menu.new
		
		session_item_shell = Gtk::ImageMenuItem.new("Interact Session")
		session_image_shell = Gtk::Image.new
		session_image_shell.set(Gtk::Stock::EXECUTE, Gtk::IconSize::MENU)
		session_item_shell.set_image(session_image_shell)
		@menu_session.append(session_item_shell)
		
		separator1 = Gtk::SeparatorMenuItem.new
		@menu_session.append(separator1)
		
		close_session_item_shell = Gtk::ImageMenuItem.new("Close Session")
		close_session_image_shell = Gtk::Image.new
		close_session_image_shell.set(Gtk::Stock::CLOSE, Gtk::IconSize::MENU)
		close_session_item_shell.set_image(close_session_image_shell)
		@menu_session.append(close_session_item_shell)

		separator2 = Gtk::SeparatorMenuItem.new
		@menu_session.append(separator2)
		
		meterpreter_proc_item_shell = Gtk::ImageMenuItem.new("Process")
		meterpreter_proc_image_shell = Gtk::Image.new
		meterpreter_proc_image_shell.set(Gtk::Stock::CLOSE, Gtk::IconSize::MENU)
		meterpreter_proc_item_shell.set_image(meterpreter_proc_image_shell)
		@menu_session.append(meterpreter_proc_item_shell)		
		
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
				elsif (event.event_type == Gdk::Event::BUTTON2_PRESS)
					path, column, x, y = treeview.get_path_at_pos(event.x, event.y)
					begin
						iter = @treeview.model.get_iter(path)
						treeview.selection.select_path(path)
						open_session(iter)
					rescue
						nil
					end					
				end
			end
		end
		
		# Items session signals
		session_item_shell.signal_connect('activate') do |item|
			if current = @selection.selected
				puts "yeah"
				open_session(current)
			end
		end
		
		close_session_item_shell.signal_connect('activate') do |item|
			if session_iter = @selection.selected
				remove_session_iter(session_iter)
			end
		end
		
		meterpreter_proc_item_shell.signal_connect('activate') do |item|
			if current = @selection.selected
				print current[O_SESSION].tunnel_peer
			end
		end
		
	end # def initialize
	
	#
	# Add an iter to the session treeview
	#
	def add_session(session)				
		iter = @model.append
		iter[ID_SESSION] = session.sid.to_s
		iter[PEER] = session.tunnel_peer
		iter[PAYLOAD] = session.via_payload ? session.via_payload : nil
		iter[O_SESSION] = session
		iter[O_BUFFER] = Gtk::TextBuffer.new
	end
	
	#
	# Open the session with the selected iter
	#
	def open_session(iter)
		session = iter[O_SESSION]
		if (session.type == "meterpreter")
			#Msf::Ui::Gtk2::Console::Meterpreter.new(iter)
			Msf::Ui::Gtk2::Console::Basic.new(iter)
		else
			Msf::Ui::Gtk2::Console::Basic.new(iter)
		end
	end
	
	#
	# Kill the session associated with this item
	# TODO: Bug on the sesson kill
	#
	def remove_session_iter(iter)
		# Just kill the session, let the event handler remove it
		iter[O_SESSION].kill
	end
	
	#
	# Remove the item from the model
	# This is called by the framework on_session_close()
	#
	def remove_session(session)
		found = nil
		@model.each do |model,path,iter|
			if (iter[ID_SESSION] == session.sid.to_s)
				found = iter
				break
			end
		end
		
		@model.remove(found) if found
	end

end # class MySessionTree

end
end
end
