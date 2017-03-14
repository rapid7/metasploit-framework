#!/usr/bin/env ruby
#
# $Id$
#
# This script parses a Metasploit module's use of the datastore to
# ensure that all datastore elements are both declared and used. Adding
# arbitrary elements to the datastore without first declaring them won't
# throw an error at runtime, but can occasionally be the cause of bugs and
# make troubleshooting more difficult.
#
# This script could use more serious option parsing, and a batch mode beyond
# bash's "for i in path/to/modules/*.rb; do verify_datastore.rb $i; done" Also,
# it assumes Metasploit's msf/core is in the load path.
#
# $Revision$
#

infile = ARGV[0]
unless(infile && File.readable?(infile))
  puts "Usage: #{$0} /path/to/module.rb"
  exit(1)
end

verbose = false

mod = File.open(infile, "rb") {|f| f.read(f.stat.size)}

regex = {}
regex[:datastore] = /[^\x2e](datastore\x5b[\x22\x27]([^\x22\x27]+))/
regex[:comment] = /^[\s]*#/
regex[:opts] = /register_options/
regex[:opts_end] = /^[\s]*def[\s]+/
regex[:is_opt] = /^[\s]*(Opt[A-Z][^\x2e]+)\x2enew[\s]*\x28?[\x22\x27]([^\x22\x27]+)/
regex[:mixin] = /^[\s]*include[\s]+([^\s]+)/
regex[:class] = /^[\s]*class[\s]+Metasploit3[\s]*<[\s]*([A-Z][^\s]+)/
# regex[:require] = /^[\s]*require[\s]+[\x22\x27]([^\x22\x27]+)[\x22\x27]/

referenced_datastores = []
declared_datastores = {}
undeclared_datastores = []
unused_datastores = []

# Declared datastore finder
mod.each_line do |line|
  next if line.match regex[:comment]
  datastores = line.scan regex[:datastore]
  datastores.each {|ds| referenced_datastores << ds[1]}
end

# Referenced datastore finder
in_opts = false
mod.each_line do |line|
  in_opts = true if line.match regex[:opts]
  in_opts = false if line.match regex[:opts_end]
  next unless in_opts
  if line.match regex[:is_opt]
    # Assumes only one!
    declared_datastores[$2] ||= $1
  end
end

# Class and Mixin finder
$mixins = []
$class = nil
require 'msf/core' # Make sure this is in your path, or else all is for naught.

mod.each_line do |line|
  if line.match regex[:class]
    $class = ObjectSpace.class_eval($1)
  elsif line.match regex[:mixin]
    mixin = $1
    begin
      $mixins << ObjectSpace.module_eval(mixin)
    rescue
      puts "[-] Error including mixin: #{mixin}"
      next
    end
  end
end

class Fakemod < $class
  $mixins.each {|m| include m}
end
fakemod = Fakemod.new
inhereted_datastores = fakemod.options.keys

undeclared_datastores = referenced_datastores - (declared_datastores.keys + inhereted_datastores)

# It's common to not use some inhereted datastores, don't bother talking about them
unused_datastores = declared_datastores.keys - referenced_datastores

if verbose
  puts "[+] --- Referenced datastore keys for #{infile}"
  referenced_datastores.uniq.sort.each {|ds| puts ds}
  puts "[+] --- Declared datastore keys for #{infile}"
  declared_datastores.keys.sort.each {|opt| puts "%-30s%s" % [opt, declared_datastores[opt]] }
end

unless undeclared_datastores.empty?
  puts "[-] %-60s : fail (undeclared)" % [infile]
  puts "[-] The following datastore elements are undeclared" if verbose
  undeclared_datastores.uniq.sort.each {|opt| puts "    \e[31m#{opt}\e[0m" }
end

unless unused_datastores.empty?
  puts "[*] %-60s : warn (unused)" % [infile]
  puts "[*] The following datastore elements are unused" if verbose
  unused_datastores.uniq.sort.each {|opt| puts "    \e[33m#{opt}\e[0m" }
end

if undeclared_datastores.empty? && unused_datastores.empty?
  puts "[+] %-60s : okay" % [infile]
end

