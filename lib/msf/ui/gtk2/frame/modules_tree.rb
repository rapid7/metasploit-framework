module Msf
module Ui
module Gtk2

	##
	# This class describe the modules treeview
	##
	class MyModuleTree < MyGlade

		@@completion = []

		PIX, NAME, MOD, DESC, TYPE = *(0..5).to_a
		DIR, EXP, AUX, PAY, ENC, NOP = *(0..5).to_a

		include Msf::Ui::Gtk2::MyControls

		def initialize(treeview, viewmodule)
			super('menu_module')

			@treeview1 = treeview
			@treeview1.enable_search = true

			@model = Gtk::TreeStore.new(
				Gdk::Pixbuf, # pixbuf
				String,		 # Module name
				Object,		 # Module object
				String,      # Description
				Fixnum		 # Module type
			)
			# Register the model for later use
			$gtk2driver.module_model = @model

			# Init buffer module with tags
			buff = SkeletonTextBuffer.new()
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
				cell.text = iter[NAME]
			end

			column_desc = Gtk::TreeViewColumn.new	
			column_desc.pack_start(renderer_module, true)
			column_desc.set_cell_data_func(renderer_module) do |column, cell, model, iter|
				cell.text = iter[DESC]
			end


			#set model to treeview
			@treeview1.set_size_request(380, -1)
			@treeview1.set_model(@model)

			@treeview1.rules_hint = true

			@selection = @treeview1.selection
			@treeview1.selection.mode = Gtk::SELECTION_BROWSE

			@treeview1.append_column(column_module)
			@treeview1.append_column(column_desc)
			
			# Signals
			@treeview1.signal_connect('cursor-changed') do |widget, event|
				widget.selection.selected_each do |model, path, iter|
				active(iter)
				end
			end

			@treeview1.signal_connect('button_press_event') do |treeview, event|
				if event.kind_of? Gdk::EventButton

					# Right click
					if (event.button == 3)
						path, column, x, y = treeview.get_path_at_pos(event.x, event.y)
						begin
							iter = @treeview1.model.get_iter(path)
							if(true)
								treeview.selection.select_path(path)
								active(iter)
								@menu_module.popup(nil, nil, event.button, event.time)
							end
						rescue
							nil
						end

						# Double click
					elsif (event.event_type == Gdk::Event::BUTTON2_PRESS)
						path, column, x, y = treeview.get_path_at_pos(event.x, event.y)
						begin
							iter = @treeview1.model.get_iter(path)

							if (iter.get_value(TYPE) == EXP)
								treeview.selection.select_path(path)
								active(iter)
								MsfAssistant::Exploit.new(iter.get_value(MOD))
							elsif (iter.get_value(TYPE) == AUX)
								treeview.selection.select_path(path)
								active(iter)
								MsfAssistant::Auxiliary.new(iter.get_value(MOD))
							elsif (iter.get_value(TYPE) == DIR)
								# Ignore
							else
								treeview.selection.select_path(path)
								active(iter)
								MsfDialog::Error.new($gtk2driver.main, "Not available")
							end

						rescue
							nil
						end
					end
				end
			end

			@one_shot.signal_connect('activate') do |item|
				if active_module = @selection.selected
					type = active_module.get_value(TYPE)
					if (type == EXP)
						MsfAssistant::Exploit.new(active_module.get_value(MOD))
					elsif (type == AUX)
						MsfAssistant::Auxiliary.new(active_module.get_value(MOD))
					elsif (type == DIR)
						# Ignore
					else
						MsfDialog::Error.new($gtk2driver.main, "Not available")
					end
				end
			end
			
			@view_code.signal_connect('activate') do |item|
				if active_module = @selection.selected
					type = active_module.get_value(TYPE)
					if (type == EXP or type == AUX)
						MsfWindow::CodeView.new(active_module.get_value(MOD))
					elsif (type == DIR)
						# Ignore
					else
						MsfDialog::Error.new($gtk2driver.main, "Not available")
					end
				end
			end
			# Add modules in the Gtk::TreeView
			add_modules()

			# Configure the module completion handles for easy reference
			$gtk2driver.module_completion = @@completion

			# Modified hyperlink code from gtk-demo
			viewmodule.signal_connect("event-after") do |viewtext, event|
				if ( 
					event.kind_of?(Gdk::EventButton) and 
					event.button == 1 and 
					event.event_type == Gdk::Event::BUTTON_PRESS
				   )

					buffer = viewtext.buffer

					# we shouldn't follow a link if the user has selected something
					range = buffer.selection_bounds
					if range and range[0].offset != range[1].offset
						false
					else

						x, y = viewtext.window_to_buffer_coords(Gtk::TextView::WINDOW_WIDGET, event.x, event.y)
						iter = viewtext.get_iter_at_location(x, y)

						tags = iter.tags
						tags.each do |tag|
							if (tag.respond_to?('href') and tag.href)
								Rex::Compat.open_browser(tag.href)
								break
							end
						end
					
						true
					end
				else
					false
				end
			end

		end # def initialize


		#
		# Add modules to a treeview store specified by hash
		#
		def add_modules_to_store(store, parent, text, entry, attrs={})
			iter = store.append(parent)
			if (entry.class == ::Hash)
					
				iter[PIX]  = driver.get_icon(attrs[:top_icon] || attrs[:dir_icon])
				iter[NAME] = text
				iter[MOD]  = nil
				iter[TYPE] = DIR
				iter[DESC] = attrs[:top_desc] || ""
				
				attrs.delete(:top_icon)
				attrs.delete(:top_desc)
				
				entry.keys.sort.each do |x|
					add_modules_to_store(store, iter, x, entry[x], attrs)
				end
			else
				iter[PIX]  = driver.get_icon(attrs[:mod_icon])
				iter[NAME] = entry.refname.split("/")[-1]
				iter[MOD]  = entry
				iter[DESC] = entry.name
				iter[TYPE] = attrs[:type]

				@@completion.push(entry.name)
			end
		end

		#
		# Prune empty module directories from the hash
		#
		def prune_hash(key, hash)
			
			cnt = 0
			
			hash.keys.each do |k|
				if(hash[k].class != ::Hash)
					cnt += 1
					next
				end
				
				num = prune_hash(k, hash[k])
				if (num == 0)
					hash.delete(k)
				end
				
				cnt += num
			end
			
			# $stdout.puts "#{key} == #{cnt}"
			
			cnt
		end

		#
		# Add Exploits module in the treeview
		#
		def add_modules(filter=/.*/)

			
			mod_exploits  = {}
			mod_auxiliary = {}
			
			if(not (@module_cache and filter == /.*/))
				
				framework.exploits.each_module do |mod, obj|

				# SEGV :(
				#	while (Gtk.events_pending?)
				#		Gtk.main_iteration
				#	end


					parts = mod.split("/")
					name  = parts.pop
					ref   = mod_exploits
					parts.each do |part|
						ref[part] ||= {}
						ref = ref[part]
					end

					ins = obj.new
					if (
						mod =~ filter or
						ins.name =~ filter or 
						ins.description.gsub(/\s+/, " ") =~ filter or 
						ins.author_to_s =~ filter or
						ins.references.map {|x| x.to_s}.join(" ") =~ filter
					   )
						ref[name] = obj.new
					end
				end

				prune_hash("exploits", mod_exploits)

				framework.auxiliary.each_module do |mod, obj|

				# SEGV :(
				#	while (Gtk.events_pending?)
				#		Gtk.main_iteration
				#	end

					parts = mod.split("/")
					name  = parts.pop
					ref   = mod_auxiliary
					parts.each do |part|
						ref[part] ||= {}
						ref = ref[part]
					end

					ins = obj.new
					if (
						mod =~ filter or
						ins.name =~ filter or 
						ins.description.gsub(/\s+/, " ") =~ filter or 
						ins.author_to_s =~ filter or
						ins.references.map {|x| x.to_s}.join(" ") =~ filter
					   )
						ref[name] = obj.new
					end
				end

				prune_hash("auxiliary", mod_auxiliary)
				
				# Cache the entire tree
				if(filter == /.*/)
					@module_cache ||= {}
					@module_cache[:exploits]  = mod_exploits
					@module_cache[:auxiliary] = mod_auxiliary
				end
				
			else
				mod_exploits  = @module_cache[:exploits]
				mod_auxiliary = @module_cache[:auxiliary]
			end
			
			add_modules_to_store(
				@model, nil, "Exploits", mod_exploits, 
				{
					:top_icon => "bug.xpm",
					:top_desc => "All loaded exploit modules (#{framework.stats.num_exploits})",
					:dir_icon => "gnome-fs-directory.xpm",
					:mod_icon => "bug.xpm",
					:type     => EXP
				}
			)

			add_modules_to_store(
				@model, nil, "Auxiliary", mod_auxiliary, 
				{
					:top_icon => "zoom.xpm",
					:top_desc => "All loaded auxiliary modules (#{framework.stats.num_auxiliary})",
					:dir_icon => "gnome-fs-directory.xpm",
					:mod_icon => "zoom.xpm",
					:type     => AUX
				}
			)

			#
			# TODO: To implement later ...
			#
			# # Add Parent "Payloads (nbr payloads)"
			# iter = @model.append(nil)
			# iter.set_value(PIX, driver.get_icon("bomb.xpm"))
			# iter.set_value(NAME, "Payloads (#{framework.stats.num_payloads})")
			# iter.set_value(MOD, nil)
			# iter.set_value(ADV, true)
			# 
			# # Add Payloads childs
			# framework.payloads.each_module do |mod, obj|
			#   next if not mod.match(filter)
			#   t_module = obj.new.name
			#   child_iter = @model.append(iter)
			#   child_iter.set_value(NAME, t_module)
			#   child_iter.set_value(MOD, obj.new)
			#   child_iter.set_value(ADV, false)
			#   child_iter.set_value(APP, "Payloads")
			#   @@completion.push(t_module)
			# end
			# 
			# # Add Parent "Nops (nbr nops)"
			# iter = @model.append(nil)
			# iter.set_value(PIX, driver.get_icon("encoders.xpm"))
			# iter.set_value(NAME, "NOPs (#{framework.stats.num_nops})")
			# iter.set_value(MOD, nil)
			# iter.set_value(ADV, true)
			# 
			# # Add nops childs
			# framework.nops.each_module do |mod, obj|
			#   next if not mod.match(filter)
			#   t_module = obj.new.name
			#   child_iter = @model.append(iter)
			#   child_iter.set_value(NAME, t_module)
			#   child_iter.set_value(MOD, obj.new)
			#   child_iter.set_value(ADV, false)
			#   child_iter.set_value(APP, "NOPs")
			#   @@completion.push(t_module)
			# end
			# 
			# # Add Parent "Encoders (nbr encoders)"
			# iter = @model.append(nil)
			# iter.set_value(PIX, driver.get_icon("encoders.xpm"))
			# iter.set_value(NAME, "Encoders (#{framework.stats.num_encoders})")
			# iter.set_value(MOD, nil)
			# iter.set_value(ADV, true)
			# 
			# # Add Encoders childs
			# framework.encoders.each_module do |mod, obj|
			#   next if not mod.match(filter)
			#   t_module = obj.new.name
			#   child_iter = @model.append(iter)
			#   child_iter.set_value(NAME, t_module)
			#   child_iter.set_value(MOD, obj.new)
			#   child_iter.set_value(ADV, false)
			#   iter.set_value(APP, "Encoders")
			#   @@completion.push(t_module)
			# end
		end # def add_modules

		#
		# Display the module information
		#
		def active(iter)
			if not iter[MOD].nil?
				@buffer.insert_module(iter.get_value(MOD))
			else
				@buffer.insert_help(iter.get_value(NAME))
			end
		end

		#
		# Refresh the module treeview with all msf modules
		#
		def refresh(filter=/.*/)
			@model.clear()
			add_modules(filter)
			@buffer.insert_help("Exploits")
		end

		#
		# remove all iters in array_iter
		#
		def remove(iter_array)

			# first loop to remove unmatched iter
			iter_array.each do |iter|
				next if iter[TYPE] == DIR
				@model.remove(iter)
			end

			return
			
			# second loop to update parent iter with child iter
			no_child = []
			@model.each do |model, path, iter|
				no_child.push(iter) if not iter.has_child?
				iter[NAME] = iter[NAME].sub(/[0-9]+/, iter.n_children.to_s)
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

	end

end
end
end
