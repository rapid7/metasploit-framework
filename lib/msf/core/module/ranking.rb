module Msf::Module::Ranking
  extend ActiveSupport::Concern

  module ClassMethods
    #
    # Returns this module's ranking.
    #
    def rank
      (const_defined?('Rank')) ? const_get('Rank') : Msf::NormalRanking
    end

    #
    # Returns this module's ranking as a string for display.
    #
    def rank_to_h
      rank_to_s.gsub('Rank', '').downcase
    end

    #
    # Returns this module's ranking as a string representation.
    #
    def rank_to_s
      Msf::RankingName[rank]
    end
  end

  #
  # Instance Methods
  #

  #
  # Returns the module's rank.
  #
  def rank
    self.class.rank
  end

  #
  # Returns the module's rank in display format.
  #
  def rank_to_h
    self.class.rank_to_h
  end

  #
  # Returns the module's rank in string format.
  #
  def rank_to_s
    self.class.rank_to_s
  end
end
