#!/usr/bin/env ruby

$: << '../lib'

$VERBOSE = true

require 'gtk'
require 'zip'

class MainApp < Gtk::Window
  def initialize
    super()
    set_usize(400, 256)
    set_title('rubyzip')
    signal_connect(Gtk::Window::SIGNAL_DESTROY) { Gtk.main_quit }

    box = Gtk::VBox.new(false, 0)
    add(box)

    @zipfile = nil
    @buttonPanel = ButtonPanel.new
    @buttonPanel.openButton.signal_connect(Gtk::Button::SIGNAL_CLICKED) do
      show_file_selector
    end
    @buttonPanel.extractButton.signal_connect(Gtk::Button::SIGNAL_CLICKED) do
      puts 'Not implemented!'
    end
    box.pack_start(@buttonPanel, false, false, 0)

    sw = Gtk::ScrolledWindow.new
    sw.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
    box.pack_start(sw, true, true, 0)

    @clist = Gtk::CList.new(%w[Name Size Compression])
    @clist.set_selection_mode(Gtk::SELECTION_BROWSE)
    @clist.set_column_width(0, 120)
    @clist.set_column_width(1, 120)
    @clist.signal_connect(Gtk::CList::SIGNAL_SELECT_ROW) do |_w, row, _column, _event|
      @selected_row = row
    end
    sw.add(@clist)
  end

  class ButtonPanel < Gtk::HButtonBox
    attr_reader :openButton, :extractButton
    def initialize
      super
      set_layout(Gtk::BUTTONBOX_START)
      set_spacing(0)
      @openButton = Gtk::Button.new('Open archive')
      @extractButton = Gtk::Button.new('Extract entry')
      pack_start(@openButton)
      pack_start(@extractButton)
    end
  end

  def show_file_selector
    @fileSelector = Gtk::FileSelection.new('Open zip file')
    @fileSelector.show
    @fileSelector.ok_button.signal_connect(Gtk::Button::SIGNAL_CLICKED) do
      open_zip(@fileSelector.filename)
      @fileSelector.destroy
    end
    @fileSelector.cancel_button.signal_connect(Gtk::Button::SIGNAL_CLICKED) do
      @fileSelector.destroy
    end
  end

  def open_zip(filename)
    @zipfile = Zip::File.open(filename)
    @clist.clear
    @zipfile.each do |entry|
      @clist.append([entry.name,
                     entry.size.to_s,
                     (100.0 * entry.compressedSize / entry.size).to_s + '%'])
    end
  end
end

mainApp = MainApp.new

mainApp.show_all

Gtk.main
