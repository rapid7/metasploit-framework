module Msf::Module::Rank
  extend ActiveSupport::Concern

  module ClassMethods
    # Returns this module's ranking as a string representation.
    #
    # @return [String] an value in `Metasploit::Model::Module::Rank::NAME_BY_NUMBER` or a key in
    #   `Metasploit::Model::Module::Rank::NUMBER_BY_NAME`
    def rank_name
      Metasploit::Model::Module::Rank::NAME_BY_NUMBER[rank_number]
    end

    # Module's numerical ranking.  Larger values are better and indicate the module is more reliable.
    #
    # @return [Integer] an value in `Metasploit::Model::Module::Rank::NUMBER_BY_NAME` or a key in
    #   `Metasploit::Model::Module::Rank::NAME_BY_NUMBER`.
    def rank_number
      unless instance_variable_defined? :@rank_number
        inherit = false

        if const_defined?('Rank', inherit)
          @rank_number = const_get('Rank', inherit)
        else
          @rank_number = Metasploit::Model::Module::Rank::NUMBER_BY_NAME['Normal']
        end
      end

      @rank_number
    end
  end

  # @!method rank_name

  # @!method rank_name
  #   (see Msf::Module::Rank::ClassMethods#rank_name)
  #
  #   @return (see Msf::Module::Rank::ClassMethods#rank_name)
  #
  # @!method rank_number
  #   (see Msf::Module::Rank::ClassMethod#rank_number)
  #
  #   @return (see Msf::Module::Rank::ClassMethods#rank_number)
  delegate :rank_name,
           :rank_number,
           to: 'self.class'
end
