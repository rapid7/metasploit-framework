# -*- coding: binary -*-
#
# frozen_string_literal: true

module Msf
  module ModuleOutputs
    module ExecutableTypes
      module EXESmall
        def initialize(info = {})
          executable_types = info['OutputExecutableTypes'] || []
          super(
              merge_info(
              info, 
              'OutputExecutableTypes' => executable_types + ['EXESmall']
              )
          )
        end
      end
    end
  end
end
