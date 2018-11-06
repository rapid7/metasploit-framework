module Nexpose
  class Tag
    # Override of filter criterion to account for proper JSON naming.
    #
    class Criterion < Nexpose::Criterion
      # Convert to Hash, which can be converted to JSON for API calls.
      def to_h
        { operator: operator,
          values: Array(value),
          field_name: field }
      end

      # Create a Criterion object from a JSON-derived Hash.
      #
      # @param [Hash] json JSON-derived Hash of a Criterion object.
      # @return [Criterion] Parsed object.
      #
      def self.parse(json)
        new(json['field_name'], json['operator'], json['values'])
      end
    end

    # Override of filter criteria to account for different parsing from JSON.
    #
    class Criteria < Nexpose::Criteria
      # Create a Criteria object from a JSON-derived Hash.
      #
      # @param [Hash] json JSON-derived Hash of a Criteria object.
      # @return [Criteria] Parsed object.
      #
      def self.parse(json)
        criteria = json['criteria'].map { |c| Criterion.parse(c) }
        new(criteria, json['operator'])
      end
    end
  end
end
