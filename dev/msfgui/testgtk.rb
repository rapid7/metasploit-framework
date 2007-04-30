#!/usr/bin/env ruby

require 'gtk2'

puts "Gtk+ v#{Gtk::MAJOR_VERSION}.#{Gtk::MINOR_VERSION}.#{Gtk::MICRO_VERSION}"
puts "Ruby/GTK2 v#{Gtk::BINDING_VERSION.join(".")}"
