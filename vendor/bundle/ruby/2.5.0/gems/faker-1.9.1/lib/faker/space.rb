module Faker
  class Space < Base
    flexible :space
    class << self
      def planet
        fetch('space.planet')
      end

      def moon
        fetch('space.moon')
      end

      def galaxy
        fetch('space.galaxy')
      end

      def nebula
        fetch('space.nebula')
      end

      def star_cluster
        fetch('space.star_cluster')
      end

      def constellation
        fetch('space.constellation')
      end

      def star
        fetch('space.star')
      end

      def agency
        fetch('space.agency')
      end

      def agency_abv
        fetch('space.agency_abv')
      end

      def nasa_space_craft
        fetch('space.nasa_space_craft')
      end

      def company
        fetch('space.company')
      end

      def distance_measurement
        rand(10..100).to_s + ' ' + fetch('space.distance_measurement')
      end

      def meteorite
        fetch('space.meteorite')
      end

      def launch_vehicule
        fetch('space.launch_vehicule')
      end
    end
  end
end
