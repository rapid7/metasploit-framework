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
    return Exploit::CheckCode::Unsupported unless has_check?

    nmod = replicant
    result = nmod.check_host(datastore['RHOST'])

    # Propagate the last_vuln_attempt (which may be the actual VulnAttempt
    # object) back from the replicant so that the ensure block in
    # job_run_proc (which calls report_failure on the *original* instance)
    # knows a vuln attempt was already created and can enrich it directly.
    if nmod.respond_to?(:last_vuln_attempt) && nmod.last_vuln_attempt && respond_to?(:last_vuln_attempt=)
      self.last_vuln_attempt = nmod.last_vuln_attempt
    end

    result
  end

end
end
