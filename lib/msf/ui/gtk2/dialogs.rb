module Msf
module Ui
module Gtk2


##
# This class perform an assistant to configure exploits
# 
# TODO:
# - Add the passive options on the first page (hdm)
##
class MsfAssistant
	
	KEY, DEFAULT, VALUE, DESC = *(0..5).to_a
	
	include Msf::Ui::Gtk2::MyControls
	
	def initialize(active_module)
		@session_tree  = $gtk2driver.session_tree
		@job_tree   = $gtk2driver.job_tree
		@active_module = active_module
		
		# initialize exploit driver's exploit instance
		@mydriver = Msf::ExploitDriver.new(framework)
		@mydriver.exploit = framework.exploits.create(@active_module.refname)
		
		@myassistant = Gtk::Assistant.new
		@myassistant.set_default_size(400, 300)
		@myassistant.set_title(@active_module.refname)
		
		# Hash to store entry assistant
		@hash = {}
		
		# signals assistant
		@myassistant.signal_connect('cancel') {
			@myassistant.hide
		}
		
		@myassistant.signal_connect('close') {
			@myassistant.hide
		}
		
		@myassistant.signal_connect('apply') {
			@myassistant.hide
		}
		
		@myassistant.signal_connect('prepare') { |assistant, page|
			update_page(page)
		}
		
		@model_required = Gtk::ListStore.new(String, String, String, String)
		@model_advanced = Gtk::ListStore.new(String, String, String, String)		
		
		# add target payload
		@target_page = target_completion()
		@myassistant.append_page(@target_page)
		@myassistant.set_page_title(@target_page, "Target")
		#@myassistant.set_page_type(page, Gtk::Assistant::PAGE_INTRO)
		@myassistant.set_page_complete(@target_page, false)
		
		# add payload frame
		@payload_page = payload_completion()
		@myassistant.append_page(@payload_page)
		@myassistant.set_page_title(@payload_page, "Payload")
		#@myassistant.set_page_type(page, Gtk::Assistant::PAGE_CONFIRM)
		@myassistant.set_page_complete(@payload_page, false)
		
		# add options frame
		@options_page = options_completion()
		@myassistant.append_page(@options_page)
		@myassistant.set_page_title(@options_page, "Options")
		@myassistant.set_page_type(@options_page, Gtk::Assistant::PAGE_CONFIRM)
		@myassistant.set_page_complete(@options_page, true)
		
		# add summary frame
		@summary_page = summary_completion()
		@myassistant.append_page(@summary_page)
		@myassistant.set_page_title(@summary_page, "Summary")
		@myassistant.set_page_type(@summary_page, Gtk::Assistant::PAGE_SUMMARY)
		@myassistant.set_page_complete(@summary_page, true)
		
		@myassistant.show_all
	end # def initialize
	
	def target_completion
		page = Gtk::VBox.new(false, 2)
		
		# Gtk::Frame for combo target entry
		frame_target = Gtk::Frame.new("Select :")
		page.pack_start(frame_target, false, false, 10)
		
		# Model for Gtk::Combo
		model_target = Gtk::ListStore.new(String, Object)
		
		# Add iter to Gtk::Combo
		@active_module.targets.each_with_index do |target, idx|
			iter = model_target.append
			iter[0] = target.name
			iter[1] = idx
		end
		
		# Gtk::ComboBox
		combo_target = Gtk::ComboBox.new(model_target)
		
		frame_target.add(combo_target)
		
		# Gtk::Frame for selected target
		selected = Gtk::Frame.new("Selected TARGET")
		page.pack_start(selected, false, false, 10)
		
		# Pack & renderer combo_all
		renderer = Gtk::CellRendererText.new
		combo_target.pack_start(renderer, true)
		combo_target.set_attributes(renderer, :text => 0)
		
		# Gtk::Label for selected payload
		label = Gtk::Label.new
		selected.add(label)
		
		# Signal for combo payload		
		combo_target.signal_connect('changed') do ||
			text = "<span foreground='blue' size='xx-large'>#{combo_target.active_iter[0]}</span>"
			label.set_markup(text)
			@hash["TARGET"] = combo_target.active_iter[1]
			@myassistant.set_page_complete(@target_page, true)
		end
		page.show_all
	end # def target_completion
	
	def payload_completion
		page = Gtk::VBox.new(false, 4)
		
		# Gtk::Frame for combo payload entry
		frame_all = Gtk::Frame.new("Payloads")

		page.pack_start(frame_all, false, false, 10)

		
		# Model for Gtk::Combox
		model_all = Gtk::ListStore.new(String, Object)
		
		# Add iter to Model
		@active_module.compatible_payloads.each do |refname, payload|
				iter = model_all.append
				iter[0] = refname
				iter[1] = payload
		end
		
		# Gtk::ComboBox
		combo_all = Gtk::ComboBox.new(model_all)
		
		# Pack & renderer combo_all
		renderer = Gtk::CellRendererText.new
		combo_all.pack_start(renderer, true)
		combo_all.set_attributes(renderer, :text => 0)

		frame_all.add(combo_all)
		
		# Gtk::Frame for description selected payload
		description = Gtk::Frame.new("Description")
		page.pack_start(description, false, false, 10)
		
		# Stuff for description payload
		textscroll = Gtk::ScrolledWindow.new
		textscroll.shadow_type = Gtk::SHADOW_IN
		textscroll.hscrollbar_policy = Gtk::POLICY_AUTOMATIC
		textscroll.vscrollbar_policy = Gtk::POLICY_AUTOMATIC
		buffer = Gtk::TextBuffer.new
		textview = Gtk::TextView.new(buffer)
		textview.set_editable(false)
		textview.set_cursor_visible(false)
		textscroll.add(textview)
		description.add(textscroll)		
		
		# Gtk::Frame for selected payload
		selected = Gtk::Frame.new("Selected PAYLOAD")
		page.pack_start(selected, false, false, 10)
		
		# Gtk::Label for selected payload
		label = Gtk::Label.new
		selected.add(label)
		
		# Signal for combo payload
		combo_all.signal_connect('changed') do
			text = "<span foreground='blue' size='xx-large'>#{combo_all.active_iter[0]}</span>"
			buffer.set_text(combo_all.active_iter[1].new.description)
			label.set_markup(text)
			@hash["PAYLOAD"] = combo_all.active_iter[0]
			@myassistant.set_page_complete(@payload_page, true)
		end

		page.show_all
	end # def payload_completion
	
	def options_completion
		page = Gtk::VBox.new(false, 2)
		
		# Gtk::Frame for required options
		frame_required = Gtk::Frame.new("Required")
		page.pack_start(frame_required, false, false, 10)
		
		# Gtk::Frame for advanced options
		frame_advanced = Gtk::Frame.new("Advanced")
		page.pack_start(frame_advanced, false, false, 10)
		
		# TreeView
		treeview_required = Gtk::TreeView.new(@model_required)
		treeview_advanced = Gtk::TreeView.new(@model_advanced)
		
		# Column
		add_columns(treeview_required, @model_required)
		add_columns(treeview_advanced, @model_advanced)
		
		# add treeview to frame
		frame_required.add(treeview_required)
		frame_advanced.add(treeview_advanced)
		
		page.show_all
	end # def options_completion
	
	def summary_completion
		return Gtk::Label.new("Summary").show
	end # def summary_completion

	def add_columns(treeview, model)
		# column for KEY
		renderer = Gtk::CellRendererText.new
		column = Gtk::TreeViewColumn.new('Name',
						renderer,
						'text' => KEY)
		column.set_sort_column_id(KEY)
		treeview.append_column(column)
		
		# column for DEFAULT
		renderer = Gtk::CellRendererText.new
		column = Gtk::TreeViewColumn.new('Default',
						renderer,
						'text' => DEFAULT)
		column.set_sort_column_id(DEFAULT)
		treeview.append_column(column)
		
		# column for VALUE
		renderer = Gtk::CellRendererText.new
		renderer.background = "#f6ffd6"
		renderer.editable = true
		renderer.signal_connect("edited") do |rend, path, text|
			updatevalue(model, VALUE, path, text)
		end
		column = Gtk::TreeViewColumn.new('Value',
						renderer,
						'text' => VALUE)
		column.set_sort_column_id(VALUE)
		column.set_resizable(true)
		treeview.append_column(column)
		
		# column for DESC
		renderer = Gtk::CellRendererText.new
		column = Gtk::TreeViewColumn.new('Description',
						renderer,
						'text' => DESC)
		column.set_sort_column_id(DESC)
		treeview.append_column(column)
	end # def add_columns
	
	def pack(model, key, opt)
		iter = model.append
		iter[KEY] = key
		iter[DEFAULT] = opt.default.to_s
		iter[DESC] = opt.desc.to_s
	end # def pack
	
	def updatevalue(model, column, path, text)
		iter = model.get_iter(path)
		iter[column] = text
		@hash[iter.get_value(KEY)] = text		
	end # def updatevalue

	def update_page(page)
		if @myassistant.get_page_title(page) == "Options"
			
			# Clear treeview
			@model_required.clear
			@model_advanced.clear
			
			# Exploits options
			@mydriver.exploit.options.sorted.each do |key, opt|
				next if (opt.evasion?)
				if (opt.required?)
					pack(@model_required, key, opt)
				else
					pack(@model_advanced, key, opt)
				end
			end
		
			# Payload options
			@mydriver.payload = framework.payloads.create(@hash["PAYLOAD"])			
			@mydriver.payload.options.each do |key, opt|
				if (opt.required?)
					pack(@model_required, key, opt)
				else
					pack(@model_advanced, key, opt)
				end
			end
		
		elsif @myassistant.get_page_title(page) == "Summary"
			
			# Import options from the supplied assistant
			@mydriver.exploit.datastore.import_options_from_hash(@hash)
			
			# Share the exploit's datastore with the payload
			@mydriver.payload.share_datastore(@mydriver.exploit.datastore)
			
			@mydriver.target_idx = (@mydriver.exploit.datastore['TARGET']).to_i
			
			@pipe = Rex::IO::BidirectionalPipe.new
			
			@mydriver.exploit.init_ui(@pipe, @pipe)
			@mydriver.payload.init_ui(@pipe, @pipe)
			
			# Session registration is done by event handler
			# XXX: No output from the exploit when this is set!
			@mydriver.use_job = true
			
			@pipe.create_subscriber_proc() do |msg|
				$stderr.puts "MSG: #{msg}"
				$gtk2driver.append_log_view(msg)
			end

			Thread.new do 
				0.upto(20) do |i|
					$pipe.print_status("I am alive at #{i}")
					select(nil, nil, nil, 1.0)
				end
			end

			
			@pipe.print_status("Launching exploit #{@mydriver.exploit.refname}...")
			
			begin
				@mydriver.run
				@job_tree.add_oneshot(@active_module, @hash["RHOST"])
			rescue ::Exception => e
				@pipe.print_error("Exploit failed: #{e}")
			end
		end
	end # def update_page
	
end # MyTargetDialog

end
end
end
