# frozen_string_literal: true

module Msf
  module Mitre
    module Attack
      module Categories
        PATHS = {
          'TA' => 'tactics',
          'DS' => 'datasources',
          'S' => 'software',
          'M' => 'mitigations',
          'A' => 'assets',
          'G' => 'groups',
          'C' => 'campaigns',
          'T' => 'techniques'
        }.freeze
      end
    end
  end
end
