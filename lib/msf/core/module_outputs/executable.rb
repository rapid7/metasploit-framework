# -*- coding: binary -*-
#
# frozen_string_literal: true

module Msf
  module ModuleOutputs
    module Executable
      def initialize(info = {})
        super(
            merge_info(
            info,
            'ModuleOutputs' => 'Executable'
            )
        )
      end
    end
  end
end
