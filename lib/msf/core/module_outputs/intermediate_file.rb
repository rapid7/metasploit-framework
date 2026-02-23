# -*- coding: binary -*-
#
# frozen_string_literal: true

# This file requires extra processing/instructions on the target.
# For example, calling off to a second executable to process, execute or compile this file
module Msf
  module ModuleOutputs
    module IntermediateFile
      def initialize(info = {})
        super(
            merge_info(
            info,
            'ModuleOutputs' => 'IntermediateFile'
            )
        )
      end
    end
  end
end
