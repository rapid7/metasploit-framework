#!/usr/bin/env ruby

$VERBOSE = true

$: << '../lib'

require 'Qt'
system('rbuic -o zipdialogui.rb zipdialogui.ui')
require 'zipdialogui.rb'
require 'zip'

a = Qt::Application.new(ARGV)

class ZipDialog < ZipDialogUI
  def initialize
    super()
    connect(child('add_button'), SIGNAL('clicked()'),
            self, SLOT('add_files()'))
    connect(child('extract_button'), SIGNAL('clicked()'),
            self, SLOT('extract_files()'))
  end

  def zipfile(&proc)
    Zip::File.open(@zip_filename, &proc)
  end

  def each(&proc)
    Zip::File.foreach(@zip_filename, &proc)
  end

  def refresh
    lv = child('entry_list_view')
    lv.clear
    each do |e|
      lv.insert_item(Qt::ListViewItem.new(lv, e.name, e.size.to_s))
    end
  end

  def load(zipfile)
    @zip_filename = zipfile
    refresh
  end

  def add_files
    l = Qt::FileDialog.getOpenFileNames(nil, nil, self)
    zipfile do |zf|
      l.each do |path|
        zf.add(File.basename(path), path)
      end
    end
    refresh
  end

  def extract_files
    selected_items = []
    unselected_items = []
    lv_item = entry_list_view.first_child
    while lv_item
      if entry_list_view.is_selected(lv_item)
        selected_items << lv_item.text(0)
      else
        unselected_items << lv_item.text(0)
      end
      lv_item = lv_item.next_sibling
    end
    puts "selected_items.size = #{selected_items.size}"
    puts "unselected_items.size = #{unselected_items.size}"
    items = !selected_items.empty? ? selected_items : unselected_items
    puts "items.size = #{items.size}"

    d = Qt::FileDialog.get_existing_directory(nil, self)
    if !d
      puts 'No directory chosen'
    else
      zipfile { |zf| items.each { |e| zf.extract(e, File.join(d, e)) } }
    end
  end

  slots 'add_files()', 'extract_files()'
end

unless ARGV[0]
  puts "usage: #{$0} zipname"
  exit
end

zd = ZipDialog.new
zd.load(ARGV[0])

a.mainWidget = zd
zd.show
a.exec
