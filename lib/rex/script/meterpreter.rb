# -*- coding: binary -*-

module Rex
module Script
class Meterpreter < Base

  begin
    include Msf::Post::Windows::Priv
    include Msf::Post::Windows::Eventlog
    include Msf::Post::Common
    include Msf::Post::Windows::Registry
    include Msf::Post::File
    include Msf::Post::Windows::Services
    include Msf::Post::Windows::Accounts
  rescue ::LoadError
  end

  def initialize(client, path)
    # The mixins for `Msf::Post::*` now assume a single info argument is present,
    # whilst `::Rex::Script::Base` assumes client and path are provided. Directly call
    # the `::Rex::Script::Base` initialize method for now. In the future Rex scripts
    # will need to be migrated to use post modules
    ::Rex::Script::Base.instance_method(:initialize).bind(self).call(client, path)
  end
end
end
end

