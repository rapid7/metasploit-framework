# -*- coding: binary -*-

module Msf
###
#
# This module provides a way of interacting with ManageEngine Xnode server as used in ADAudit Plus and DataSecurity Plus
#
###
  module Auxiliary:: ManageengineXnode
    include Msf::Auxiliary::Report
    include Msf::Auxiliary::ManageengineXnode::Action
    include Msf::Auxiliary::ManageengineXnode::Config
    include Msf::Auxiliary::ManageengineXnode::Interact
    include Msf::Auxiliary::ManageengineXnode::Process

    def initialize(info = {})
      super

      register_options(
        [
          Msf::OptString.new('USERNAME', [true, 'Username used to authenticate to the Xnode server', 'atom']),
          Msf::OptString.new('PASSWORD', [true, 'Password used to authenticate to the Xnode server', 'chegan']),
        ], Msf::Auxiliary::ManageengineXnode
      )
    end
  end
end
