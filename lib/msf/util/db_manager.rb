module Msf
  module Util
    module DBManager
      # Creates search conditions to match the specified search string against all of the model's columns.
      #
      # @param model - An ActiveRecord model object
      # @param search - A string regex search
      # @return Arel::Nodes::Or object that represents a search of all of the model's columns
      def self.create_all_column_search_conditions(model, search)
        search = "(?mi)#{search}"
        condition_set = model.columns.map do |column|
          Arel::Nodes::Regexp.new(Arel::Nodes::NamedFunction.new("CAST", [model.arel_table[column.name].as("TEXT")]),
                                  Arel::Nodes.build_quoted(search))
        end
        condition_set.reduce { |conditions, condition| conditions.or(condition).expr }
      end
    end
  end
end
