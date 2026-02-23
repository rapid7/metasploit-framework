# -*- coding: binary -*-
#
# frozen_string_literal: true

module Msf
  module ModuleOutputs
    module ExecutableTypes
      module EXEService
        def initialize(info = {})
          executable_types = info['OutputExecutableTypes'] || []
          super(
              merge_info(
              info, 
              'OutputExecutableTypes' => executable_types + ['EXEService']
              )
          )
        end
      end
    end
  end
end
