# -*- coding: binary -*-
module Msf
module Ui

###
#
# Module that contains some most excellent banners.
#
###
module Banner

  #
  # Returns a specific metasploit logo. If the specified file is a relative path
  # then the file will be searched for first in the included local directory,
  # then in the user-specific directory.
  #
  def self.readfile(fname)
    pathname = fname

    unless File.absolute_path(pathname) == pathname
      if File.readable?(File.join(::Msf::Config.logos_directory, fname))
        pathname = File.join(::Msf::Config.logos_directory, fname)
      elsif File.readable?(File.join(::Msf::Config.user_logos_directory, fname))
        pathname = File.join(::Msf::Config.user_logos_directory, fname)
      end
    end

    fdata = "<< Missing banner: #{pathname} >>"
    begin
      raise ArgumentError unless File.readable?(pathname)
      raise ArgumentError unless File.stat(pathname).size < 65_536
      fdata = File.open(pathname) {|f| f.read f.stat.size}
    rescue SystemCallError, ArgumentError
      nil
    end
    return fdata
  end

  def self.to_s
    return self.readfile ENV['MSFLOGO'] if ENV['MSFLOGO']

    logos = []

    # Easter egg (always a cow themed logo): export/set GOCOW=1
    if ENV['GOCOW']
      logos.concat(Dir.glob(::Msf::Config.logos_directory + File::SEPARATOR + 'cow*.txt'))
    # Easter egg (always a halloween themed logo): export/set THISISHALLOWEEN=1
    elsif ( ENV['THISISHALLOWEEN'] || Time.now.strftime("%m%d") == "1031" )
      logos.concat(Dir.glob(::Msf::Config.logos_directory + File::SEPARATOR + '*.hwtxt'))
    elsif ( ENV['APRILFOOLSPONIES'] || Time.now.strftime("%m%d") == "0401" )
      logos.concat(Dir.glob(::Msf::Config.logos_directory + File::SEPARATOR + '*.aftxt'))
    else
      logos.concat(Dir.glob(::Msf::Config.logos_directory + File::SEPARATOR + '*.txt'))
      logos.concat(Dir.glob(::Msf::Config.user_logos_directory + File::SEPARATOR + '*.txt'))
    end

    logos = logos.map { |f| File.absolute_path(f) }
    self.readfile logos[rand(logos.length)]
  end
end

end
end
