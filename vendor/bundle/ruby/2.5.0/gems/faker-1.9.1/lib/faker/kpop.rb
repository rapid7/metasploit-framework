module Faker
  class Kpop < Base
    class << self
      def i_groups
        fetch('kpop.i_groups')
      end

      def ii_groups
        fetch('kpop.ii_groups')
      end

      def iii_groups
        fetch('kpop.iii_groups')
      end

      def girl_groups
        fetch('kpop.girl_groups')
      end

      def boy_bands
        fetch('kpop.boy_bands')
      end

      def solo
        fetch('kpop.solo')
      end
    end
  end
end
