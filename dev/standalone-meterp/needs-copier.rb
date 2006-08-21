#!/usr/bin/env ruby

DRY = false

@dst = ARGV[0]
if !@dst
	puts "usage: <dest dir>"
	exit(1)
end

def make_dirs(path)
	pieces = File.join(@dst, path).split(File::Separator)
	pieces.length.times do |i|
		path = File.join(*pieces[0, i+1])
		if !File.exists?(path)
			puts "Making #{path}"
			Dir.mkdir(path) if !DRY
		end
	end
end

def add_dir(name)
	# make sure the base dirs are created
	make_dirs(File.dirname(name))

	path = File.join(@dst, File.dirname(name))

	puts "Running cp -vR #{name} #{path}"
	system('cp', '-vR', name, path) if !DRY
end
def add_file(name)
	add_dir(name)
end

def del_dir(name)
	path = File.join(@dst, name)
	puts "Running rm -rf #{path}"
	system('rm', '-rf', path) if !DRY
end
def del_file(name)
	del_dir(name)
end

$stdin.each_line do |line|
	(add, type, name) = line.chomp.split(' ')
	meth = ((add == '+' ? 'add_' : 'del_') + type).to_sym
	send(meth, name)
end
