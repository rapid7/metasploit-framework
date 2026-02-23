# -*- coding: binary -*-
#
# frozen_string_literal: true

module Msf
  module ModuleInputs
    module Payload
      def initialize(info = {})
        super(
            merge_info(
            info,
            'ModuleInputs' => 'Payload'
            )
        )
      end
    end
  end
end
