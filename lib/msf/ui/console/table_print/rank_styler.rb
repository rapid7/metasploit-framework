# -*- coding: binary -*-

module Msf
  module Ui
    module Console
      module TablePrint
        class RankStyler

          def style(rank)
            case rank
            when Msf::RankingName[Msf::GreatRanking]
              "%grn#{rank}%clr"
            when Msf::RankingName[Msf::ExcellentRanking]
              "%grn#{rank}%clr"
            else
              rank.to_s
            end
          end
        end
      end
    end
  end
end
