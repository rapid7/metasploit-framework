# -*- coding: binary -*-

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# https://metasploit.com/framework/
##


module Msf
  module Sessions
    module CreateSessionOptions
      def initialize(info = {})
        super(info)

        register_options(
          [
            OptBool.new('CreateSession', [false, 'Create a new session for every successful login', true])
          ]
        )
      end
    end
  end
end
