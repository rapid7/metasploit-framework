# -*- coding: binary -*-

module Msf
###
#
# This module provides a way of interacting with ManageEngine Xnode server
# as used in ADAudit Plus and DataSecurity Plus
#
###
  module Auxiliary::ManageEngineXnode
    include Msf::Auxiliary::ManageEngineXnode::Action
    include Msf::Auxiliary::ManageEngineXnode::BasicChecks
    include Msf::Auxiliary::ManageEngineXnode::Config
    include Msf::Auxiliary::ManageEngineXnode::Interact
    include Msf::Auxiliary::ManageEngineXnode::Process

    def initialize(info = {})
      super

      register_options(
        [
          Msf::OptString.new('USERNAME', [true, 'Username used to authenticate to the Xnode server', 'atom']),
          Msf::OptString.new('PASSWORD', [true, 'Password used to authenticate to the Xnode server', 'chegan']),
        ], Msf::Auxiliary::ManageEngineXnode
      )
    end
  end
end
