module Msf
module Ui
module Wx
module MyControls

	#
	# Included class methods
	#

	# Get the global driver handle
	def driver
		$wxdriver
	end
	
	# Return the framework instance from the driver handler
	def framework
		driver.framework
	end

	def log(msg)
		if ($wxlogger)
			$wxlogger.append_text(msg + "\n")
		else
			$stderr.puts Time.now.to_s + " " + msg
		end
	end

	#
	# Controls
	# 

class MyModuleTree < ::Wx::TreeCtrl
    def initialize(parent, id,pos, size,style)
        super(parent, id, pos, size, style)
		evt_left_dclick { |event| on_dclick(event) }
	end
	
	def on_dclick(event)
#		$stderr.puts "Double clicked!"
	end
end


class MyPanel < ::Wx::Panel

	attr_reader :m_note_modules, :m_note_console, :m_panel_exploits, :m_panel_payloads
	attr_reader :m_panel_encoders, :m_panel_sessions, :m_panel_jobs, :m_nops

    def initialize(frame,x,y,w,h)
        super( frame, -1, ::Wx::Point.new(x, y), ::Wx::Size.new(w, h) )
		
		@m_size_panelv  = ::Wx::BoxSizer.new( ::Wx::VERTICAL )
		@m_size_panelh  = ::Wx::BoxSizer.new( ::Wx::HORIZONTAL )
		
		@m_note_modules = ::Wx::Notebook.new(self, NOTE_MODULES)
		@m_panel_info   = ::Wx::Panel.new( self )
		@m_note_console = ::Wx::Notebook.new(self, NOTE_CONSOLE)		

		@m_panel_info.set_background_colour(::Wx::Colour.new('gray'))

		# Create the tabbed tree view pages
		@m_panel_exploits = ::Wx::Panel.new(@m_note_modules)
		@m_panel_payloads = ::Wx::Panel.new(@m_note_modules)
		@m_panel_sessions = ::Wx::Panel.new(@m_note_modules)
		@m_panel_jobs     = ::Wx::Panel.new(@m_note_modules)
		
		@m_note_modules.add_page(@m_panel_exploits, 'Exploits')
		@m_note_modules.add_page(@m_panel_payloads, 'Payloads')	
		@m_note_modules.add_page(@m_panel_sessions, 'Sessions')
		@m_note_modules.add_page(@m_panel_jobs, 'Jobs')	
	
		# Create the info pages
		@m_panel_inf = ::Wx::Panel.new(@m_note_console)
		@m_panel_log = ::Wx::Panel.new(@m_note_console)
		@m_panel_con = ::Wx::Panel.new(@m_note_console)
		
		# Create each page of the notebook
		@m_note_console.add_page(@m_panel_inf, 'Information')
		@m_note_console.add_page(@m_panel_log, 'Attack Log')
		@m_note_console.add_page(@m_panel_con, 'Console')

		# Create the information text control
		c = ::Wx::LayoutConstraints.new
		c.top.same_as( @m_panel_inf, ::Wx::LAYOUT_TOP, 2 )
		c.height.percent_of( @m_panel_inf, ::Wx::LAYOUT_BOTTOM, 95 )
		c.left.same_as( @m_panel_inf, ::Wx::LAYOUT_LEFT, 2 )
		c.width.percent_of( @m_panel_inf, ::Wx::LAYOUT_WIDTH, 99 )
		
        @m_text_inf = ::Wx::TextCtrl.new(
			@m_panel_inf, -1,
			"",
			::Wx::Point.new(0, 250), 
			::Wx::Size.new(100, 50), 
			::Wx::NO_BORDER |
			::Wx::TE_READONLY |
			::Wx::TE_MULTILINE 
		)
		@m_text_inf.set_constraints(c)
		
		# Create the log text control
		c = ::Wx::LayoutConstraints.new
		c.top.same_as( @m_panel_log, ::Wx::LAYOUT_TOP, 2 )
		c.height.percent_of( @m_panel_log, ::Wx::LAYOUT_BOTTOM, 95 )
		c.left.same_as( @m_panel_log, ::Wx::LAYOUT_LEFT, 2 )
		c.width.percent_of( @m_panel_log, ::Wx::LAYOUT_WIDTH, 99 )
		
        @m_text_log = ::Wx::TextCtrl.new(
			@m_panel_log, -1,
			"",
			::Wx::Point.new(0, 250), 
			::Wx::Size.new(100, 50), 
			::Wx::NO_BORDER |
			::Wx::TE_READONLY |
			::Wx::TE_MULTILINE 
		)
		@m_text_log.set_constraints(c)
		
		# Set the global logger instance
		$wxlogger = @m_text_log
		
		# Create the console text control
		c = ::Wx::LayoutConstraints.new
		c.top.same_as( @m_panel_con, ::Wx::LAYOUT_TOP, 2 )
		c.height.percent_of( @m_panel_con, ::Wx::LAYOUT_BOTTOM, 95 )
		c.left.same_as( @m_panel_con, ::Wx::LAYOUT_LEFT, 2 )
		c.width.percent_of( @m_panel_con, ::Wx::LAYOUT_WIDTH, 99 )
		
        @m_text_con = ::Wx::TextCtrl.new(
			@m_panel_con, -1,
			"",
			::Wx::Point.new(0, 250), 
			::Wx::Size.new(100, 50), 
			::Wx::NO_BORDER |
			::Wx::TE_READONLY |
			::Wx::TE_MULTILINE 
		)
		@m_text_con.set_constraints(c)
		@m_text_con.append_text("*** The console has not been implemented yet\n msf> ")
		
		
		# Configure auto-layout (ADD EVERY PANEL TO THIS!)
		[
			self,
			@m_panel_info,
			@m_panel_exploits,
			@m_panel_payloads,
			@m_panel_sessions,
			@m_panel_jobs,
			@m_panel_log,
			@m_panel_con,
			@m_panel_inf
		].each { |panel| panel.set_auto_layout( TRUE ) }
		
		# Add each panel or notebook to the size
		@m_size_panelv.add(@m_note_modules)
		@m_size_panelv.add(@m_panel_info)
		@m_size_panelv.add(@m_note_console)
			
		# Configure the sizer
		set_sizer(@m_size_panelv)
		
		# Add the event hook
		evt_size {|event| on_size(event) }
	end
	
	def on_module_select(mod)
		
		@m_text_inf.clear
		
		inst = mod.new
		buff =
			"\n" +
			"Type: " + inst.type + "\n"    +
			"Path: " + inst.refname + "\n"  +
			"Name: " + inst.name + "\n"
		
		inst.description.each_line do |line|
			buff << line.strip + "\n"
		end

		@m_text_inf.write_text(buff)
	end

	def on_module_dclick(mod)	
		Wx::MessageBox.new("You clicked on #{mod.refname}")
	end
		
	def on_size(event)
		size = get_client_size()
		x = size.get_width
		y = size.get_height
		b = 4	
		
		if (@m_note_modules)
			@m_note_modules.set_dimensions( b, b, percent(40, x)-b, percent(65, y)-b )
		end
		
		if (@m_panel_info)
			@m_panel_info.set_dimensions( percent(40, x)+b, b, percent(60, x), percent(65, y))
		end
		
		if (@m_note_console)
			@m_note_console.set_dimensions( b, percent(65, y)+b, x-b, percent(35, y)-b )
		end		
	end	
	
	
	def percent(mine, total)
		((mine.to_f / 100.0) * total).to_i
	end
	
end

	
end
end
end
end
