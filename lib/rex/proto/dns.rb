# -*- coding: binary -*-

module Rex
module Proto
module DNS

  module Constants
    MATCH_HOSTNAME= /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])(\.?))+([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]\.*?)$/
    MATCH_FQDN = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]\.*)$/
  end

end
end
end

