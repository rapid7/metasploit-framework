# -*- coding: binary -*-
module Rex
module Parser

###
#
# This class parses the contents of an INI file.
#
###
class Ini < Hash

  ##
  #
  # Factories
  #
  ##

  #
  # Creates a new class instance and reads in the contents of the supplied
  # file path.
  #
  def self.from_file(path)
    ini = Ini.new(path)
    ini.from_file
    return ini
  end

  #
  # Creates a new class instance from the supplied string.
  #
  def self.from_s(str)
    ini = Ini.new
    ini.from_s(str)
    return ini
  end

  #
  # Initializes an ini instance and tries to read in the groups from the
  # file if it exists.
  #
  def initialize(path = nil)
    self.path = path

    # Try to synchronize ourself with the file if we
    # have one
    begin
      self.from_file if (self.path)
    rescue
    end
  end

  alias each_group each_key

  #
  # Adds a group of the supplied name if it doesn't already exist.
  #
  def add_group(name = 'global', reset = true)
    self[name] = {} if (reset == true)
    self[name] = {} if (!self[name])

    return self[name]
  end

  #
  # Checks to see if name is a valid group.
  #
  def group?(name)
    return (self[name] != nil)
  end

  ##
  #
  # Serializers
  #
  ##

  #
  # Reads in the groups from the supplied file path or the instance's file
  # path.
  #
  def from_file(fpath = nil)
    fpath = path if (!fpath)

    read_groups(fpath)
  end

  #
  # Reads in the groups from the supplied string.
  #
  def from_s(str)
    read_groups_string(str.split("\n"))
  end

  #
  # Writes the group settings to a file.
  #
  def to_file(tpath = nil)
    tpath = path if (!tpath)

    f = File.new(tpath, "w")
    f.write(to_s)
    f.close
  end

  #
  # Converts the groups to a string.
  #
  def to_s
    str = ''
    keys.sort.each { |k|
      str << "[#{k}]\n"

      self[k].each_pair { |var, val|
        str << "#{var}=#{val}\n"
      }

      str << "\n";
    }

    return str
  end

  attr_reader :path

protected

  #
  # Reads in the groups and their attributes from the supplied file
  # path or from the instance's file path if one was set.
  #
  def read_groups(fpath) # :nodoc:
    if (!fpath)
      raise ArgumentError, "No file path specified.",
        caller
    end

    # Read in the contents of the file
    lines = ::IO.readlines(fpath)

    # Now read the contents from the supplied string
    read_groups_string(lines)
  end

  #
  # Reads groups from the supplied string
  #
  def read_groups_string(str) # :nodoc:
    # Reset the groups hash
    self.clear

    # The active group
    active_group = nil

    # Walk each line initializing the groups
    str.each { |line|
      next if (line.match(/^;/))

      # Eliminate cr/lf
      line.gsub!(/(\n|\r)/, '')

      # Is it a group [bob]?
      if (md = line.match(/^\[(.+?)\]/))
        active_group = md[1]
        self[md[1]]  = {}
      # Is it a VAR=VAL?
      elsif (md = line.match(/^(.+?)=(.*)$/))
        if (active_group)
          var, val = md[1], md[2]

          # don't clobber datastore nils with ""
          unless val.empty?
            self[active_group][var] = val
          end
        end
      end
    }
  end

  attr_writer :path # :nodoc:

end

end
end
