# -*- coding: binary -*-

module Msf

###
#
# This module provides methods for modules which intend to handle multiple hosts
# themselves through some means, e.g. scanners. This circumvents the typical
# RHOSTS -> RHOST logic offered by the framework.
#
###

module Auxiliary::MultipleTargetHosts

  def has_check?
    respond_to?(:check_host)
  end

  def check
    nmod = replicant
    begin
      nmod.check_host(datastore['RHOST'])
    rescue NoMethodError
      Exploit::CheckCode::Unsupported
    end
  end

end
end
