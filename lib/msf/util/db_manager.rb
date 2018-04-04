module Msf
module Util
module DBManager
  # Creates search conditions to match the specified search string against all of the model's columns.
  #
  # @param model - An ActiveRecord model object
  # @param search - A string regex search
  # @param column_name_skip_list - An array of strings containing column names to skip
  # @return Arel::Nodes::Or object that represents a search of all of the model's columns
  def self.create_all_column_search_conditions(model, search, column_name_skip_list=nil)
    search = "(?mi)#{search}"
    # remove skip columns
    columns = model.columns.reject { |column|
      column_name_skip_list && column_name_skip_list.include?(column.name)
    }

    condition_set = columns.map { |column|
      Arel::Nodes::Regexp.new(Arel::Nodes::NamedFunction.new("CAST", [model.arel_table[column.name].as("TEXT")]),
                              Arel::Nodes.build_quoted(search))
    }
    condition_set.reduce { |conditions, condition| conditions.or(condition).expr }
  end

  def self.process_opts_workspace(opts, framework)
    wspace = delete_opts_workspace(opts)
    if wspace.nil? || ((wspace.kind_of? String) && wspace.empty?)
      raise ArgumentError.new("opts must include a valid :workspace.")
    end

    if wspace.kind_of? String
      wspace = framework.db.find_workspace(wspace)
    end
    wspace
  end

  def self.delete_opts_workspace(opts)
    opts.delete(:workspace) || opts.delete(:wspace)
  end
end
end
end
