# -*- coding: binary -*-
require 'rex/powershell/payload'
require 'rex/powershell/output'
require 'rex/powershell/parser'
require 'rex/powershell/obfu'
require 'rex/powershell/param'
require 'rex/powershell/function'
require 'rex/powershell/script'
require 'rex/powershell/psh_methods'
require 'rex/powershell/command'


module Rex
  module Powershell
    #
    # Reads script into a PowershellScript
    #
    # @param script_path [String] Path to the Script File
    #
    # @return [Script] Powershell Script object
    def self.read_script(script_path)
      Rex::Powershell::Script.new(script_path)
    end

    #
    # Insert substitutions into the powershell script
    # If script is a path to a file then read the file
    # otherwise treat it as the contents of a file
    #
    # @param script [String] Script file or path to script
    # @param subs [Array] Substitutions to insert
    #
    # @return [String] Modified script file
    def self.make_subs(script, subs)
      if ::File.file?(script)
        script = ::File.read(script)
      end

      subs.each do |set|
        script.gsub!(set[0], set[1])
      end

      script
    end

    #
    # Return an array of substitutions for use in make_subs
    #
    # @param subs [String] A ; seperated list of substitutions
    #
    # @return [Array] An array of substitutions
    def self.process_subs(subs)
      return [] if subs.nil? or subs.empty?
      new_subs = []
      subs.split(';').each do |set|
        new_subs << set.split(',', 2)
      end

      new_subs
    end
  end
end
