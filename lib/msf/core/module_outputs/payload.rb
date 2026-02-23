# -*- coding: binary -*-
#
# frozen_string_literal: true

module Msf
  module ModuleOutputs
    module Payload
      def initialize(info = {})
        super(
            merge_info(
            info,
            'ModuleOutputs' => 'Payload'
            )
        )
      end
    end
  end
end
