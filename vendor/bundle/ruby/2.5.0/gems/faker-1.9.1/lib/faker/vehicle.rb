module Faker
  class Vehicle < Base
    flexible :vehicle

    VIN_CHARS = '0123456789.ABCDEFGH..JKLMN.P.R..STUVWXYZ'.freeze
    VIN_MAP = '0123456789X'.freeze
    VIN_WEIGHTS = '8765432X098765432'.freeze

    class << self
      # ISO 3779
      def vin
        _, wmi, wmi_ext = sample(fetch_all('vehicle.manufacture'))

        c = VIN_CHARS.split('').reject { |n| n == '.' }
        vehicle_identification_number = wmi.split('').concat(Array.new(14) { sample(c) })
        (12..14).to_a.each_with_index { |n, i| vehicle_identification_number[n] = wmi_ext[i] } unless wmi_ext.nil?
        vehicle_identification_number[10] = fetch('vehicle.year')
        vehicle_identification_number[8] = vin_checksum(vehicle_identification_number)

        vehicle_identification_number.join.upcase
      end

      def manufacture
        sample(fetch_all('vehicle.manufacture')).first
      end

      def mileage
        rand_in_range(10_000, 90_000)
      end

      def year
        rand_in_range(2005, ::Time.now.year)
      end

      def make
        fetch('vehicle.makes')
      end

      def model(make_of_model = '')
        return fetch("vehicle.models_by_make.#{make}") if make_of_model.empty?
        fetch("vehicle.models_by_make.#{make_of_model}")
      end

      def make_and_model
        m = make
        "#{m} #{model(m)}"
      end

      def style
        fetch('vehicle.styles')
      end

      def color
        fetch('vehicle.colors')
      end

      def transmission
        fetch('vehicle.transmissions')
      end

      def drive_type
        fetch('vehicle.drive_types')
      end

      def fuel_type
        fetch('vehicle.fuel_types')
      end

      def door_count
        "#{fetch('vehicle.door_count')} #{fetch('vehicle.door')}"
      end

      def car_type
        fetch('vehicle.car_types')
      end

      def engine
        "#{fetch('vehicle.engine_size')} #{fetch('vehicle.cylinder_engine')}"
      end
      alias engine_size engine

      def car_options
        Array.new(rand(5...10)) { fetch('vehicle.car_options') }
      end

      def standard_specs
        Array.new(rand(5...10)) { fetch('vehicle.standard_specs') }
      end

      private

      def calculate_vin_weight(character, idx)
        (VIN_CHARS.index(character) % 10) * VIN_MAP.index(VIN_WEIGHTS[idx])
      end

      def vin_checksum(vehicle_identification_number)
        VIN_MAP[vehicle_identification_number.each_with_index.map(&method(:calculate_vin_weight)).inject(:+) % 11]
      end
    end
  end
end
