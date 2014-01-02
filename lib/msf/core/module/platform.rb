# -*- coding: binary -*-
require 'abbrev'

#
# This is the definitions of which Platforms the framework knows about.  The
# relative ranks are used to support ranges, and the Short names are used to
# allow for more convenient specification of the platforms....
#

class Msf::Module::Platform

  Rank  = 0
  # actually, having a argument of '' is what to do for wanting 'all'
  Short = "all"

  class << self
    attr_accessor :full_name
  end

  #
  # Returns the "real" name of the module instance, accouting for potentially
  # aliased class names.
  #
  def self.realname
    # Use the cached version if one has been set
    return full_name if (full_name)

    # Otherwise, generate it and cache it
    names = []
    c     = Msf::Module::Platform
    name.split('::')[3 .. -1].each { |part|
      c = c.const_get(part)
      if (c.const_defined?('RealName') == true)
        names << c.const_get('RealName')
      else
        names << part
      end
    }
    full_name = names.join(' ')
  end

  #
  # Calls the class method.
  #
  def find_children
    self.class.find_children
  end

  #
  # The magic to try to build out a Platform from a string.
  #
  def self.find_platform(str)
    # remove any whitespace and downcase
    str = str.gsub(' ', '').downcase

    # Start at the base platform module
    mod = ::Msf::Module::Platform

    # Scan forward, trying to find the end module
    while str.length > 0
      mod, str = find_portion(mod, str)
    end

    return mod
  end

  #
  # Finds all inherited children from a given module.
  #
  def self.find_children
    @subclasses ||= []
    @subclasses.sort_by { |a| a::Rank }
  end

  def self.inherited(subclass)
    @subclasses ||= []
    @subclasses << subclass
  end

  #
  # Builds the abbreviation set for every module starting from
  # a given point.
  #
  def self.build_child_platform_abbrev(mod)
    # Flush out any non-class and non-inherited children
    children = mod.find_children

    # No children to speak of?
    return if (children.length == 0)

    # Build the list of names & rankings
    names  = {}
    ranked = {}

    children.map { |c|
      name = c.name.split('::')[-1].downcase

      # If the platform has an alias, such as a portion that may
      # start with an integer, use that as the name
      if (c.const_defined?('Alias'))
        als = c.const_get('Alias').downcase

        names[als]  = c
        ranked[als] = c::Rank
      # If the platform has more than one alias, process the list
      elsif (c.const_defined?('Aliases'))
        c.const_get('Aliases').each { |a|
          a = a.downcase

          names[a]  = c
          ranked[a] = c::Rank
        }
      end

      names[name]  = c
      ranked[name] = c::Rank
    }

    # Calculate their abbreviations
    abbrev = ::Abbrev::abbrev(names.keys)

    # Set the ranked list and abbreviated list on this module,
    # then walk the children
    mod.const_set('Abbrev', abbrev)
    mod.const_set('Ranks', ranked)
    mod.const_set('Names', names)
  end

  #
  # Finds the module that best matches the supplied string (or a portion of
  # the string).
  #
  def self.find_portion(mod, str)

    # Check to see if we've built the abbreviated cache
    if (not (
          mod.const_defined?('Abbrev') and
          mod.const_defined?('Names') and
          mod.const_defined?('Ranks')
        )    )
      build_child_platform_abbrev(mod)
    end

    if (not mod.const_defined?('Names'))
      elog("Failed to instantiate the platform list for module #{mod}")
      raise RuntimeError.new("Failed to instantiate the platform list for module #{mod}")
      return nil
    end

    abbrev   = mod.const_get('Abbrev')
    names    = mod.const_get('Names')
    ranks    = mod.const_get('Ranks')
    best     = nil
    bestlen  = 0
    bestmat  = nil
    bestrank = 0

    # Walk through each abbreviation
    abbrev.each { |a|
      # If the abbreviation is too long, no sense in scanning it
      next if (a[0].length > str.length)

      # If the current abbreviation matches with the
      # supplied string and is better than the previous
      # best match length, use it, but only if it also
      # has a higher rank than the previous match.
      if ((a[0] == str[0, a[0].length]) and
          (a[0].length > bestlen) and
          (bestrank == nil or bestrank <= ranks[a[1]]))
        best     = [ names[a[1]], str[a[0].length .. -1] ]
        bestlen  = a[0].length
        bestmat  = a[0]
        bestrank = ranks[a[1]]
      end
    }

    # If we couldn't find a best match at this stage, it's time to warn.
    if (best == nil)
      raise ArgumentError, "No classes in #{mod} for #{str}!", caller
    end

    return best
  end

  private_class_method :build_child_platform_abbrev # :nodoc:
  private_class_method :find_portion # :nodoc:

  ##
  #
  # Builtin platforms
  #
  ##

  #
  # Windows
  #
  class Windows < Msf::Module::Platform
    Rank  = 100
    # Windows 95
    class W95 < Windows
      Rank = 100
      Alias = "95"
      RealName = "95"
    end

    # Windows 98
    class W98 < Windows
      Rank = 100
      Alias = "98"
      RealName = "98"
      class FE < W98
        Rank = 100
      end
      class SE < W98
        Rank = 200
      end
    end

    # Windows ME
    class ME < Windows
      Rank = 100
    end

    # Windows NT
    class NT < Windows
      Rank = 100
      class SP0 < NT
        Rank = 100
      end
      class SP1 < NT
        Rank = 200
      end
      class SP2 < NT
        Rank = 300
      end
      class SP3 < NT
        Rank = 400
      end
      class SP4 < NT
        Rank = 500
      end
      class SP5 < NT
        Rank = 600
      end
      class SP6 < NT
        Rank = 700
      end
      class SP6a < NT
        Rank = 800
      end
    end

    # Windows 2000
    class W2000 < Windows
      Rank = 200
      Aliases = [ "2000", "2K" ]
      RealName = "2000"
      class SP0 < W2000
        Aliases = [ "sp0-4", "sp0-sp4" ]
        Rank = 100
      end
      class SP1 < W2000
        Rank = 200
      end
      class SP2 < W2000
        Rank = 300
      end
      class SP3 < W2000
        Rank = 400
      end
      class SP4 < W2000
        Rank = 500
      end
    end

    # Windows XP
    class XP < Windows
      Rank = 300
      class SP0 < XP
        # It's not clear whether this should be assigned to the lower
        # or higher bound of the range.
        Aliases = [ "sp0-1", "sp0/1", "sp0-sp1", "sp0/sp1", "sp0-2", "sp0-sp2", "sp0-3", "sp0-sp3" ]
        Rank = 100
      end
      class SP1 < XP
        Rank = 200
      end
      class SP2 < XP
        Rank = 300
      end
      class SP3 < XP
        Rank = 400
      end
    end

    # Windows 2003 Server
    class W2003 < Windows
      Rank = 400
      Aliases = [ "2003", "2003 Server", "2K3" ]
      RealName = "2003"
      class SP0 < W2003
        Rank = 100
      end
      class SP1 < W2003
        Rank = 200
      end
    end

    class Vista < Windows
      Rank = 500
      class SP0 < Vista
        Aliases = [ "sp0-1", "sp0/1", "sp0-sp1", "sp0/sp1" ]
        Rank = 100
      end
      class SP1 < Vista
        Rank = 200
      end
    end

    class W7 < Windows
      Rank = 600
      RealName = "7"
    end

    class W8 < Windows
      Rank = 700
      RealName = "8"
    end
  end

  #
  # NetWare
  #
  class Netware < Msf::Module::Platform
    Rank = 100
    Alias = "netware"
  end

  #
  # Android
  #
  class Android < Msf::Module::Platform
    Rank = 100
    Alias = "android"
  end

  #
  # Java
  #
  class Java < Msf::Module::Platform
    Rank = 100
    Alias = "java"
  end

  #
  # Ruby
  #
  class Ruby < Msf::Module::Platform
    Rank = 100
    Alias = "ruby"
  end

  #
  # Linux
  #
  class Linux < Msf::Module::Platform
    Rank = 100
    Alias = "linux"
  end

  #
  # Cisco
  #
  class Cisco < Msf::Module::Platform
    Rank = 100
    Alias = "cisco"
  end

  #
  # Solaris
  #
  class Solaris < Msf::Module::Platform
    Rank = 100
    class V4
      Rank = 100
      Alias = "4"
    end
    class V5
      Rank = 200
      Alias = "5"
    end
    class V6
      Rank = 300
      Alias = "6"
    end
    class V7
      Rank = 400
      Alias = "7"
    end
    class V8
      Rank = 500
      Alias = "8"
    end
    class V9
      Rank = 600
      Alias = "9"
    end
    class V10
      Rank = 700
      Alias = "10"
    end
  end

  #
  # OSX
  #
  class OSX < Msf::Module::Platform
    Rank = 100
  end

  #
  # Generic BSD
  #
  class BSD < Msf::Module::Platform
    Rank = 100
  end

  #
  # OpenBSD
  #
  class OpenBSD < Msf::Module::Platform
    Rank = 100
  end

  #
  # BSDi
  #
  class BSDi < Msf::Module::Platform
    Rank = 100
  end

  #
  # NetBSD
  #
  class NetBSD < Msf::Module::Platform
    Rank = 100
  end

  #
  # FreeBSD
  #
  class FreeBSD < Msf::Module::Platform
    Rank = 100
  end

  #
  # AIX
  #
  class AIX < Msf::Module::Platform
    Rank = 100
    Alias = "aix"
  end

  #
  # HP-UX
  #
  class HPUX < Msf::Module::Platform
    Rank = 100
    Alias = "hpux"
  end

  #
  # Irix
  #
  class Irix < Msf::Module::Platform
    Rank = 100
    Alias = "irix"
  end

  #
  # Generic Unix
  #
  class Unix < Msf::Module::Platform
    Rank = 100
    Alias = "unix"
  end

  #
  # Generic PHP
  #
  class PHP < Msf::Module::Platform
    Rank = 100
    Alias = "php"
  end

  #
  # JavaScript
  #
  class JavaScript < Msf::Module::Platform
    Rank = 100
    Alias = "js"
  end

  #
  # Python
  #
  class Python < Msf::Module::Platform
    Rank = 100
    Alias = "python"
  end

  #
  # Node.js
  #
  class NodeJS < Msf::Module::Platform
    Rank = 100
    Alias = "nodejs"
  end

  #
  # Firefox
  #
  class Firefox < Msf::Module::Platform
    Rank = 100
    Alias = "firefox"
  end
end
