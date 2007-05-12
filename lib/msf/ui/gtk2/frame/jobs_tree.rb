module Msf
module Ui
module Gtk2

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
    
end

end
end
end