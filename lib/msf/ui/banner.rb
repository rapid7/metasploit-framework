# -*- coding: binary -*-
module Msf
module Ui

###
#
# Module that contains some most excellent banners.
#
###
module Banner

  Logos =
  %w{
    branded-longhorn.txt
    cow-head.txt
    cowsay.txt
    figlet.txt
    i-heart-shells.txt
    metasploit-shield.txt
    missile-command.txt
    ninja.txt
    null-pointer-deref.txt
    r7-metasploit.txt
    wake-up-neo.txt
    workflow.txt
    3kom-superhack.txt
  }

  #
  # Returns a random metasploit logo.
  #
  def self.readfile(fname)
    base = File.expand_path(File.dirname(__FILE__))
    pathname = File.join(base, "logos", fname)
    fdata = "<< Missing banner: #{fname} >>"
    begin
      raise ArgumentError unless File.readable?(pathname)
      raise ArgumentError unless File.stat(pathname).size < 4096
      fdata = File.open(pathname) {|f| f.read f.stat.size}
    rescue SystemCallError, ArgumentError
      nil
    end
    return fdata
  end

  def self.to_s
    # Easter egg (always a cow themed logo): export/set GOCOW=1
    if ENV['GOCOW']
      case rand(3)
        when 0
          # branded-longhorn
          self.readfile Logos[0]
        when 1
          # cow-head
          self.readfile Logos[1]
        else
          # cowsay
          self.readfile Logos[2]
        end
    else
      self.readfile Logos[rand(Logos.length)]
    end
  end
end

end
end
