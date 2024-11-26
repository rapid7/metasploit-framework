# -*- coding: binary -*-

module Msf
  module Ui
    module Console
      module TablePrint
        class RankFormatter
          def format(rank)
            if rank.present? && !rank.to_s.match?(/\D/) && Msf::RankingName.key?(rank.to_i)
              Msf::RankingName[rank.to_i]
            else
              rank
            end
          end
        end
      end
    end
  end
end
