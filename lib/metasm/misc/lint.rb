#!/usr/bin/ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# this is a ruby code cleaner tool
# it passes its argument to ruby -v -c, which displays warnings (eg unused variable)
# it shows the incriminated line along the warning, to help identify false positives
# probably linux-only, and need ruby-1.9.1 or newer

def lint(tg)
  if File.symlink?(tg)
    # nothing
  elsif File.directory?(tg)
    Dir.entries(tg).each { |ent|
      next if ent == '.' or ent == '..'
      ent = File.join(tg, ent)
      lint(ent) if File.directory?(ent) or ent =~ /\.rb$/
    }
  else
    lint_file(tg)
  end
end

def lint_file(tg)
  flines = nil
  compile_warn(tg).each_line { |line|
    file, lineno, warn = line.split(/\s*:\s*/, 3)
    if file == tg
      if not flines
        puts "#{tg}:"
        flines = File.readlines(file) #File.open(file, 'rb') { |fd| fd.readlines }
      end
      puts " l.#{lineno}: #{warn.strip}: #{flines[lineno.to_i-1].strip.inspect}"
    end
  }
  puts if flines
end

def compile_warn(tg)
  r, w = IO.pipe('binary')
  if !fork
    r.close
    $stderr.reopen w
    $stdout.reopen '/dev/null'
    exec 'ruby', '-v', '-c', tg
    exit!
  else
    w.close
  end
  r
end

ARGV << '.' if ARGV.empty?
ARGV.each { |arg| lint arg }

