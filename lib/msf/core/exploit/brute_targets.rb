# -*- coding: binary -*-
module Msf

###
#
# This module allows a compatible exploit to be called once for every valid target,
# in succession, until no targets are left.
#
###
module Exploit::BruteTargets


# Compatible exploit modules define a method call exploit_target, which is called once
# for every target in the list. The very first target should always be a stub for enabling
# the brute force mode.

def exploit(*args)
  # Brute force through every available target
  if (not datastore['TARGET'] or datastore['TARGET'].to_i == 0)

    print_status("Brute forcing with #{(targets.length - 1)} possible targets")

    targets.each_index do |i|
      next if i == 0
      break if session_created?
      print_status("Trying target #{targets[i].name}...")
      exploit_target(targets[i])
    end

  # Otherwise, only try the specified target
  else
    exploit_target(target())
  end

end



end
end
