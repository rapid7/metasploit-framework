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
    wake-up-neo.txt
    cow-head.txt
    r7-metasploit.txt
    figlet.txt
    i-heart-shells.txt
    branded-longhorn.txt
    cowsay.txt
    3kom-superhack.txt
    missile-command.txt
    null-pointer-deref.txt
    metasploit-shield.txt
    ninja.txt
    workflow.txt
  }

	#
	# Returns a random metasploit logo.
	#

  def self.readfile(fname)
    base = File.expand_path(File.dirname(__FILE__))
    File.open(File.join(base, "logos", fname)) {|f| f.read f.stat.size}
  end

	def self.to_s
		if ENV['GOCOW']
			case rand(2)
				when 0
					self.readfile Logos[1]
				when 1
					self.readfile Logos[5]
			end
		else
			self.readfile Logos[rand(Logos.length)]
		end
	end

end

end
end

