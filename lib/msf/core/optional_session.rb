# -*- coding: binary -*-
#
# frozen_string_literal: true

# A mixin used for providing Modules with post-exploitation options and helper methods
#
module Msf
  module OptionalSession
    include Msf::SessionCompatibility
  end
end
