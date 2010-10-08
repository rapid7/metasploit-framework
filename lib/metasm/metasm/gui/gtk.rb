#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'gtk2'

module Metasm
module Gui

module Protect
	@@lasterror = Time.now
	def protect
		yield
	rescue Object
		puts $!.message, $!.backtrace	# also dump on stdout, for c/c
		delay = Time.now-@@lasterror
		sleep 1-delay if delay < 1	# msgbox flood protection
		@@lasterror = Time.now
		messagebox([$!.message, $!.backtrace].join("\n"), $!.class.name)
	end
end

module Msgbox
	include Protect

	def toplevel
		if self.kind_of? Gtk::Window
			self
		else
			super()
		end
	end

	# shows a message box (non-modal)
	# args: message, title/optionhash
	def messagebox(*a)
		MessageBox.new(toplevel, *a)
	end

	# asks for user input, yields the result (unless 'cancel' clicked)
	# args: prompt, :text => default text, :title => title
	def inputbox(*a)
		InputBox.new(toplevel, *a) { |*ya| protect { yield(*ya) } }
	end

	# asks to chose a file to open, yields filename
	# args: title, :path => path
	def openfile(*a)
		OpenFile.new(toplevel, *a) { |*ya| protect { yield(*ya) } }
	end

	# same as openfile, but for writing a (new) file
	def savefile(*a)
		SaveFile.new(toplevel, *a) { |*ya| protect { yield(*ya) } }
	end

	# displays a popup showing a table, yields the selected row
	# args: title, [[col0 title, col1 title...], [col0 val0, col1 val0...], [val1], [val2]...]
	def listwindow(*a)
		ListWindow.new(toplevel, *a) { |*ya| protect { yield(*ya) } }
	end
end

# clipboard = Gtk::Clipboard.get(Gdk::Selection::CLIPBOARD)
# text = clipboard.wait_for_text
# clipboard.text = 'foo'

# a widget that holds many other widgets, and displays only one of them at a time
class ContainerChoiceWidget < Gtk::Notebook
	include Msgbox

	attr_accessor :views, :view_indexes
	def initialize(*a)
		super()
		self.show_border = false
		self.show_tabs = false
		@views = {}
		@view_indexes = []

		signal_connect('realize') { initialize_visible } if respond_to? :initialize_visible

		initialize_widget(*a)

		show_all
	end

	def view(i)
		@views[i]
	end

	def showview(i)
		set_page @view_indexes.index(i)
	end

	def addview(name, w)
		@view_indexes << name
		@views[name] = w
		append_page(w, Gtk::Label.new(name.to_s))
	end

	def curview
		@views[curview_index]
	end

	def curview_index
		return if page == -1
		@view_indexes[page]
	end
end

class ContainerVBoxWidget < Gtk::VBox
	include Msgbox

	def initialize(*a)
		super()

		signal_connect('realize') { initialize_visible } if respond_to? :initialize_visible

		signal_connect('size_request') { |w, alloc| resize(*alloc) } if respond_to? :resize

		self.spacing = 2

		initialize_widget(*a)
	end

	def resize_child(cld, w, h)
		pk = query_child_packing(cld)
		if h <= 0
			pk[0] = true
			h = 1
		else
			pk[0] = false
		end
		return if h == cld.allocation.height
		set_child_packing(cld, *pk)
		cld.set_height_request(h)
	end

	def redraw
	end
end

class DrawableWidget < Gtk::DrawingArea
	include Msgbox

	attr_accessor :parent_widget, :caret_x, :caret_y, :hl_word
	# this hash is used to determine the colors of the Gui elements (background, caret, ...)
	# modifications to it are only useful before the widget is first rendered (IE before Gui.main)
	attr_accessor :default_color_association

	# keypress event keyval traduction table
	Keyboard_trad = Gdk::Keyval.constants.grep(/^GDK_/).inject({}) { |h, cst|
		v = Gdk::Keyval.const_get(cst)
		key = cst.to_s.sub(/^GDK_/, '').sub(/^KP_/, '')
		if key.length == 1
			key = key[0]	# ?a, ?b etc
		else
			key = key.downcase.to_sym
			key = {
			:page_up => :pgup, :page_down => :pgdown, :next => :pgdown,
			:escape => :esc, :return => :enter, :l1 => :f11, :l2 => :f12,
			:prior => :pgup,

			:space => ?\ ,
			:asciitilde => ?~, :quoteleft => ?`,
			:exclam => ?!, :at => ?@,
			:numbersign => ?#, :dollar => ?$,
			:percent => ?%, :asciicircum => ?^,
			:ampersand => ?&, :asterisk => ?*,
			:parenleft => ?(, :parenright => ?),
			:bracketleft => ?[, :bracketright => ?],
			:braceleft => ?{, :braceright => ?},
			:less  => ?<, :greater  => ?>,
			:quotedbl => ?", :quoteright => ?',
			:coma => ?,, :period => ?.,
			:colon => ?:, :semicolon => ?;,
			:slash => ?/, :equal => ?=,
			:plus => ?+, :minus => ?-,
			:question => ??, :backslash => ?\\,
			:underscore  => ?_, :bar => ?|,
			:comma => ?,,
			:divide => ?/, :multiply => ?*,
			:subtract => ?-, :add => ?+
			}.fetch(key, key)
		end

		h.update v => key
	}

	def initialize(*a)
		@parent_widget = nil

		@caret_x = @caret_y = 0		# text cursor position
		@oldcaret_x = @oldcaret_y = 1
		@hl_word = nil

		@layout = Pango::Layout.new Gdk::Pango.context	# text rendering

		@color = {}
		@default_color_association = {:background => :palegrey}

		super()

		# events callbacks
		signal_connect('expose_event') {
			@w = window ; @gc = Gdk::GC.new(@w)
			protect { paint }
			@w = @gc = nil
			true
		}

		signal_connect('size_allocate') { |w, alloc|
			protect { resized(alloc.width, alloc.height) }
		}

		signal_connect('button_press_event') { |w, ev|
			if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK
				next protect { click_ctrl(ev.x, ev.y) } if ev.event_type == Gdk::Event::Type::BUTTON_PRESS and ev.button == 1 and respond_to? :click_ctrl
				next
			end
			case ev.event_type
			when Gdk::Event::Type::BUTTON_PRESS
				grab_focus
				case ev.button
				when 1; protect { click(ev.x, ev.y) } if respond_to? :click
				when 3; protect { rightclick(ev.x, ev.y) } if respond_to? :rightclick
				end
			when Gdk::Event::Type::BUTTON2_PRESS
				case ev.button
				when 1; protect { doubleclick(ev.x, ev.y) } if respond_to? :doubleclick
				end
			end
		}

		signal_connect('motion_notify_event') { |w, ev|
			if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK
				protect { mousemove_ctrl(ev.x, ev.y) } if respond_to? :mousemove_ctrl
			else
				protect { mousemove(ev.x, ev.y) }
			end
		} if respond_to? :mousemove

		signal_connect('button_release_event') { |w, ev|
			protect { mouserelease(ev.x, ev.y) } if ev.button == 1
		} if respond_to? :mouserelease

		signal_connect('scroll_event') { |w, ev|
			dir = case ev.direction
			when Gdk::EventScroll::Direction::UP; :up
			when Gdk::EventScroll::Direction::DOWN; :down
			else next
			end
			if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK
				protect { mouse_wheel_ctrl(dir, ev.x, ev.y) } if respond_to? :mouse_wheel_ctrl
			else
				protect { mouse_wheel(dir, ev.x, ev.y) }
			end
		} if respond_to? :mouse_wheel

		signal_connect('key_press_event') { |w, ev|
			key = Keyboard_trad[ev.keyval]
			if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK
				protect { keypress_ctrl(key) or (@parent_widget and @parent_widget.keypress_ctrl(key)) }
			else
				protect { keypress(key) or (@parent_widget and @parent_widget.keypress(key)) }
			end
		}

		signal_connect('realize') {
			{ :white => 'fff', :palegrey => 'ddd', :black => '000', :grey => '444',
			  :red => 'f00', :darkred => '800', :palered => 'fcc',
			  :green => '0f0', :darkgreen => '080', :palegreen => 'cfc',
			  :blue => '00f', :darkblue => '008', :paleblue => 'ccf',
			  :yellow => 'ff0', :darkyellow => '440', :paleyellow => 'ffc',
			}.each { |tag, val|
				@color[tag] = color(val)
			}

			set_color_association @default_color_association

			initialize_visible if respond_to? :initialize_visible
		}

		initialize_widget(*a)

		# receive keyboard/mouse signals
		set_events Gdk::Event::ALL_EVENTS_MASK
		set_can_focus true
		set_font 'courier 10'
	end


	# create a color from a 'rgb' description
	def color(val)
		if not @color[val]
			@color[val] = Gdk::Color.new(*val.unpack('CCC').map { |c| (c.chr*4).hex })
			window.colormap.alloc_color(@color[val], true, true)
		end
		@color[val]
	end

	def set_caret_from_click(x, y)
		@caret_x = (x-1).to_i / @font_width
		@caret_y = y.to_i / @font_height
		update_caret
	end

	# change the font of the widget
	# arg is a Gtk Fontdescription string (eg 'courier 10')
	def set_font(descr)
		@layout.font_description = Pango::FontDescription.new(descr)
		@layout.text = 'x'
		@font_width, @font_height = @layout.pixel_size
		gui_update
	end

	# change the color association
	# arg is a hash function symbol => color symbol
	# color must be allocated
	# check #initialize/sig('realize') for initial function/color list
	def set_color_association(hash)
		hash.each { |k, v| @color[k] = color(v) }
		modify_bg Gtk::STATE_NORMAL, @color[:background]
		gui_update
	end

	# update @hl_word from a line & offset, return nil if unchanged
	def update_hl_word(line, offset)
		return if not line
		word = line[0...offset].to_s[/\w*$/] << line[offset..-1].to_s[/^\w*/]
		word = nil if word == ''
		@hl_word = word if @hl_word != word
	end

	def paint
	end

	# invalidate the whole widget area
	def redraw
		invalidate(0, 0, 1000000, 1000000)
	end

	def invalidate_caret(cx, cy, x=0, y=0)
		invalidate(x + cx*@font_width, y + cy*@font_height, 2, @font_height)
	end

	def invalidate(x, y, w, h)
		return if not window
		window.invalidate Gdk::Rectangle.new(x, y, w, h), false
	end

	def width
		allocation.width
	end

	def height
		allocation.height
	end

	def resized(w, h)
		redraw
	end

	def keypress(key)
	end

	def keypress_ctrl(key)
	end

	def gui_update
		redraw
	end

	def draw_color(col)
		@gc.set_foreground color(col)
	end

	def draw_rectangle(x, y, w, h)
		@w.draw_rectangle(@gc, true, x, y, w, h)
	end

	def draw_rectangle_color(col, x, y, w, h)
		draw_color(col)
		draw_rectangle(x, y, w, h)
	end

	def draw_line(x, y, ex, ey)
		@w.draw_line(@gc, x, y, ex, ey)
	end

	def draw_line_color(col, x, y, ex, ey)
		draw_color(col)
		draw_line(x, y, ex, ey)
	end

	def draw_string(x, y, str)
		@layout.text = str
		@w.draw_layout(@gc, x, y, @layout)
	end

	def draw_string_color(col, x, y, str)
		draw_color(col)
		draw_string(x, y, str)
	end
end

module WindowPos
	def x; position[0]; end
	def x=(nx); move(nx, position[1]); end
	def y; position[1]; end
	def y=(ny); move(position[0], ny); end
	def width; size[0] ; end
	def width=(nw); resize(nw, size[1]); end
	def height; size[1] ; end
	def height=(nh); resize(size[0], nh); end
end

class MessageBox < Gtk::MessageDialog
	include WindowPos
	def initialize(owner, str, opts={})
		owner = nil if owner and (not owner.kind_of? Gtk::Window or owner.destroyed?)
		owner ||= Gtk::Window.toplevels.first
		opts = {:title => opts} if opts.kind_of? String
		super(owner, Gtk::Dialog::DESTROY_WITH_PARENT, INFO, BUTTONS_CLOSE, str)
		self.title = opts[:title] if opts[:title]
		signal_connect('response') { destroy }
		show_all
		present		# bring the window to the foreground & set focus
	end
end

class InputBox < Gtk::Dialog
	include WindowPos
	attr_accessor :label, :textwidget

	# shows a simplitic input box (eg window with a 1-line textbox + OK button), yields the text
	# TODO history, dropdown, autocomplete, contexts, 3D stereo surround, etc
	def initialize(owner, str, opts={})
		owner ||= Gtk::Window.toplevels.first
		super(nil, owner, Gtk::Dialog::DESTROY_WITH_PARENT,
			[Gtk::Stock::OK, Gtk::Dialog::RESPONSE_ACCEPT], [Gtk::Stock::CANCEL, Gtk::Dialog::RESPONSE_REJECT])
		self.title = opts[:title] if opts[:title]

		@label = Gtk::Label.new(str)
		@textwidget  = Gtk::TextView.new
		if opts[:text]
			@textwidget.buffer.text = opts[:text].to_s
			@textwidget.buffer.move_mark('selection_bound', @textwidget.buffer.start_iter)
			@textwidget.buffer.move_mark('insert', @textwidget.buffer.end_iter)
		end

		@textwidget.signal_connect('key_press_event') { |w, ev|
			case ev.keyval
			when Gdk::Keyval::GDK_Escape; response(RESPONSE_REJECT) ; true
			when Gdk::Keyval::GDK_Return, Gdk::Keyval::GDK_KP_Enter; response(RESPONSE_ACCEPT) ; true
			end
		}

		signal_connect('response') { |win, id|
			resp = @textwidget.buffer.text if id == RESPONSE_ACCEPT
			destroy
			yield resp.strip if resp
			true
		}

		vbox.pack_start label, false, false, 8
		vbox.pack_start @textwidget, false, false, 8

		Gtk::Drag.dest_set(self,
				   Gtk::Drag::DEST_DEFAULT_MOTION |
				   Gtk::Drag::DEST_DEFAULT_DROP,
   				   [['text/plain', 0, 0], ['text/uri-list', 0, 0]],
				   Gdk::DragContext::ACTION_COPY | Gdk::DragContext::ACTION_MOVE)
		
		signal_connect('drag_data_received') { |w, dc, x, y, data, info, time|
			dc.targets.each { |target|
				next if target.name != 'text/plain' and target.name != 'text/uri-list'
				data.data.each_line { |l|
					l = l.chomp.sub(%r{^file://}, '')
					self.text = l
				}
			}
			Gtk::Drag.finish(dc, true, false, time)
		}


		show_all
		present
	end

	def text ; @textwidget.buffer.text ; end
	def text=(nt) ; @textwidget.buffer.text = nt ; end
end

class OpenFile < Gtk::FileChooserDialog
	include WindowPos
	@@currentfolder = nil

	# shows an asynchronous FileChooser window, yields the chosen filename
	# TODO save last path
	def initialize(owner, title, opts={})
		owner ||= Gtk::Window.toplevels.first
		super(title, owner, Gtk::FileChooser::ACTION_OPEN, nil,
		[Gtk::Stock::CANCEL, Gtk::Dialog::RESPONSE_CANCEL], [Gtk::Stock::OPEN, Gtk::Dialog::RESPONSE_ACCEPT])
		f = opts[:path] || @@currentfolder
		self.current_folder = f if f
		signal_connect('response') { |win, id|
			if id == Gtk::Dialog::RESPONSE_ACCEPT
				file = filename
				@@currentfolder = File.dirname(file)
			end
			destroy
			yield file if file
			true
		}

		show_all
		present
	end
end

class SaveFile < Gtk::FileChooserDialog
	include WindowPos
	@@currentfolder = nil

	# shows an asynchronous FileChooser window, yields the chosen filename
	# TODO save last path
	def initialize(owner, title, opts={})
		owner ||= Gtk::Window.toplevels.first
		super(title, owner, Gtk::FileChooser::ACTION_SAVE, nil,
		[Gtk::Stock::CANCEL, Gtk::Dialog::RESPONSE_CANCEL], [Gtk::Stock::SAVE, Gtk::Dialog::RESPONSE_ACCEPT])
		f = opts[:path] || @@currentfolder
		self.current_folder = f if f
		signal_connect('response') { |win, id|
			if id == Gtk::Dialog::RESPONSE_ACCEPT
				file = filename
				@@currentfolder = File.dirname(file)
			end
			destroy
			yield file if file
			true
		}

		show_all
		present
	end
end

class ListWindow < Gtk::Dialog
	include WindowPos
	# shows a window with a list of items
	# the list is an array of arrays, displayed as String
	# the first array is the column names
	# each item clicked yields the block with the selected iterator, double-click also close the popup
	def initialize(owner, title, list, h={})
		owner ||= Gtk::Window.toplevels.first
		super(title, owner, Gtk::Dialog::DESTROY_WITH_PARENT)

		cols = list.shift

		treeview = Gtk::TreeView.new
		treeview.model = Gtk::ListStore.new(*[String]*cols.length)
		treeview.selection.mode = Gtk::SELECTION_NONE

		cols.each_with_index { |col, i|
			crt = Gtk::CellRendererText.new
			tvc = Gtk::TreeViewColumn.new(col, crt)
			tvc.sort_column_id = i
			tvc.set_cell_data_func(crt) { |_tvc, _crt, model, iter| _crt.text = iter[i] }
			treeview.append_column tvc
		}

		list.each { |e|
			iter = treeview.model.append
			e.each_with_index { |v, i| iter[i] = v.to_s }
		}

		treeview.model.set_sort_column_id(0)

		treeview.signal_connect('cursor_changed') { |x|
			if iter = treeview.selection.selected
				yield iter
			end
		}
		treeview.signal_connect('row_activated') { destroy }

		signal_connect('destroy') { h[:ondestroy].call } if h[:ondestroy]

		remove vbox
		add Gtk::ScrolledWindow.new.add(treeview)
		toplevel.set_default_size cols.length*120, 400

		show if not h[:noshow]

		# so that the 1st line is not selected by default
		treeview.selection.mode = Gtk::SELECTION_SINGLE
	end

	def show
		show_all
		present
	end
end

class Window < Gtk::Window
	include WindowPos
	include Msgbox

	attr_accessor :menu
	def initialize(*a)
		super()

		signal_connect('destroy') { destroy_window }

		@vbox = Gtk::VBox.new
		add @vbox

		@menu = Gtk::MenuBar.new
		@accel_group = Gtk::AccelGroup.new

		@vbox.add @menu, 'expand' => false
		@child = nil
		s = Gdk::Screen.default
		set_default_size s.width*3/4, s.height*3/4

		Gtk::Settings.default.gtk_menu_bar_accel = nil	# disable F10 -> focus menubar

		(@@mainwindow_list ||= []) << self

		initialize_window(*a)
		build_menu
		
		
		Gtk::Drag.dest_set(self,
				   Gtk::Drag::DEST_DEFAULT_MOTION |
				   Gtk::Drag::DEST_DEFAULT_DROP,
   				   [['text/plain', 0, 0], ['text/uri-list', 0, 0]],
				   Gdk::DragContext::ACTION_COPY | Gdk::DragContext::ACTION_MOVE)
		
		signal_connect('drag_data_received') { |w, dc, x, y, data, info, time|
			dc.targets.each { |target|
				next if target.name != 'text/plain' and target.name != 'text/uri-list'
				data.data.each_line { |l|
					next if not @child or not @child.respond_to? :dragdropfile
					l = l.chomp.sub(%r{^file://}, '')
					protect { @child.dragdropfile(l) }
				}
			}
			Gtk::Drag.finish(dc, true, false, time)
		}

		show_all
	end

	def destroy_window
		@@mainwindow_list.delete self
		Gui.main_quit if @@mainwindow_list.empty?	# XXX we don't call main_start ourself..
	end

	def widget=(w)
		@vbox.remove @child if @child
		@child = w
		@vbox.add w if w
	end

	def widget
		@child
	end

	def build_menu
	end

	def new_menu
		Gtk::Menu.new
	end

	def addsubmenu(menu, *args, &action)
		stock = (Gtk::Stock.constants.map { |c| c.to_s } & args).first
		args.delete stock if stock
		accel = args.grep(/^\^?(\w|<\w+>)$/).first
		args.delete accel if accel
		check = args.delete :check
		submenu = args.grep(Gtk::Menu).first
		args.delete submenu if submenu
		label = args.shift

		if stock
			item = Gtk::ImageMenuItem.new(Gtk::Stock.const_get(stock))
			begin
				item.label = label if label
			rescue
				# in some version of gtk, no #label=
				item = Gtk::MenuItem.new(label) if label
			end
		elsif check
			item = Gtk::CheckMenuItem.new(label)
			item.active = args.shift
		elsif label
			item = Gtk::MenuItem.new(label)
		else
			item = Gtk::MenuItem.new
		end
		item.set_submenu(submenu) if submenu

		if accel
			key = accel[-1]
			if key == ?>
				key = accel[/<(.*)>/, 1]
				key = case key
				when 'enter'; Gdk::Keyval::GDK_Return
				when 'esc'; Gdk::Keyval::GDK_Escape
				when 'tab'; Gdk::Keyval::GDK_Tab
				when /^f(\d\d?)$/i; Gdk::Keyval.const_get("GDK_#{key.upcase}")
				else ??
				end
			end
			item.add_accelerator('activate', @accel_group, key, (accel[0] == ?^ ? Gdk::Window::CONTROL_MASK : 0), Gtk::ACCEL_VISIBLE)
		end
		if action
			a = action
			if check
				a = lambda { item.active = action.call(item.active?) }
			end
			item.signal_connect('activate') { protect { a.call(item) } }
		end
		menu.append item
		item
	end
end

# start the Gui main loop
def self.main
	Gtk.main
end

# ends the Gui main loop
def self.main_quit
	Gtk.main_quit
end

# register a proc to be run whenever the gui loop is idle
# if the proc returns nil/false, delete it
def self.idle_add(&b)
	Gtk.idle_add(&b)
end

# run a single iteration of the main_loop
# e.g. call this from time to time when doing heavy computation, to keep the UI somewhat responsive
def self.main_iter
	Gtk.main_iteration_do(false)
end

end
end

require 'metasm/gui/dasm_main'
require 'metasm/gui/debug'

