###
#
# Target-specific brute force information, such as the addresses
# to step, the step size (if the framework default is bad), and
# other stuff.
#
###
class Msf::Module::Target::Bruteforce < Hash

  #
  # Initializes a brute force target from the supplied brute forcing
  # information.
  #
  def initialize(hash)
    update(hash)
  end

  #
  # Returns a hash of addresses that should be stepped during
  # exploitation and passed in to the bruteforce exploit
  # routine.
  #
  def start_addresses
    if (self['Start'] and self['Start'].kind_of?(Hash) == false)
      return {'Address' => self['Start'] }
    else
      return self['Start']
    end
  end

  #
  # Returns a hash of addresses that should be stopped at once
  # they are reached.
  #
  def stop_addresses
    if (self['Stop'] and self['Stop'].kind_of?(Hash) == false)
      return {'Address' => self['Stop'] }
    else
      return self['Stop']
    end
  end

  #
  # The step size to use, or zero if the framework should figure
  # it out.
  #
  def step_size
    self['Step'] || 0
  end

  #
  # Returns the default step direction.  -1 indicates that brute forcing
  # should go toward lower addresses.  1 indicates that brute forcing
  # should go toward higher addresses.
  #
  def default_direction
    dd = self['DefaultDirection']

    if (dd and dd.to_s.match(/(-1|backward)/i))
      return -1
    end

    return 1
  end

  #
  # The delay to add between attempts
  #
  def delay
    self['Delay'].to_i || 0
  end
end
