#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# Reads untest payload modules from log/untested-payloads.log (which can be produced by running `rake spec`) and prints
# the statements that need to be added to `spec/modules/payloads_spec.rb`. **Note: this script depends on the payload
# being loadable, so if module is not loadable, then the developer must manually determine which single needs to be tested
# or which combinations of stages and stagers need to be tested.**
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'
require 'msf/core'
require 'msf/base'

framework = Msf::Simple::Framework.create()

options_set_by_ancestor_reference_name = Hash.new { |hash, ancestor_reference_name|
  hash[ancestor_reference_name] = Set.new
}

framework.payloads.each { |reference_name, payload_class|
  module_ancestors = payload_class.ancestors.select { |ancestor|
    # need to use try because name may be nil for anonymous Modules
    ancestor.name.try(:start_with?, 'Msf::Modules::')
  }
  ancestor_reference_names = module_ancestors.map { |module_ancestor|
    unpacked_module_ancestor_full_name = module_ancestor.name.sub(/^Msf::Modules::Mod/, '')
                                                             .sub(/::MetasploitModule/, '')
    module_ancestor_full_name = [unpacked_module_ancestor_full_name].pack("H*")
    module_ancestor_full_name.sub(%r{^payload/}, '')
  }

  options = {
    reference_name: reference_name,
    ancestor_reference_names: ancestor_reference_names
  }

  # record for both ancestor_reference_names as which is untested is not known here
  ancestor_reference_names.each do |ancestor_reference_name|
    options_set_by_ancestor_reference_name[ancestor_reference_name].add options
  end
}

tested_options = Set.new

$stderr.puts "Add the following context to `spec/modules/payloads_spec.rb` by inserting them in lexical order between the pre-existing contexts:"

File.open('log/untested-payloads.log') { |f|
  f.each_line do |line|
     ancestor_reference_name = line.strip

     options_set = options_set_by_ancestor_reference_name[ancestor_reference_name]

     options_set.each do |options|
       # don't print a needed test twice
       unless tested_options.include? options
         reference_name = options[:reference_name]

         $stdout.puts
         $stdout.puts "  context '#{reference_name}' do\n" \
                      "    it_should_behave_like 'payload cached size is consistent',\n" \
                      "                          ancestor_reference_names: ["

         ancestor_reference_names = options[:ancestor_reference_names]

         if ancestor_reference_names.length == 1
           $stdout.puts "                            '#{ancestor_reference_names[0]}'"
         else
           $stdout.puts "                            '#{ancestor_reference_names[1]}',"
           $stdout.puts "                            '#{ancestor_reference_names[0]}'"
         end

         $stdout.puts "                          ],\n" \
                      "                          dynamic_size: false,\n" \
                      "                          modules_pathname: modules_pathname,\n" \
                      "                          reference_name: '#{reference_name}'\n" \
                      "  end"

         tested_options.add options
       end
     end
  end
}
