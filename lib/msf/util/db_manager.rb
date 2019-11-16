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

  # Processes the workspace value in the opts hash from a request. This method throws an exception if
  # :workspace was not present but required was true, deletes the workspace from the hash, and
  # looks up the workspace object by name, which it returns.
  #
  # @param [Hash] opts The opts hash passed in from the data request. Should contain :workspace if required is true.
  # @param [Msf::Framework] framework A framework object containing a valid database connection.
  # @param [Bool] required true if the :workspace key is required for this data operation. false if it is only optional.
  # @raise [ArgumentError] opts must include a valid :workspace
  # @raise [RuntimeError] couldn't find workspace
  # @return [Mdm::Workspace] The workspace object that was referenced by name in opts.
  def self.process_opts_workspace(opts, framework, required = true)
    wspace = delete_opts_workspace(opts)
    if required && (wspace.nil? || (wspace.kind_of?(String) && wspace.empty?))
      raise ArgumentError.new("opts must include a valid :workspace")
    end

    case wspace
    when Hash
      workspace_name = wspace[:name]
    when String
      workspace_name = wspace
    when Mdm::Workspace
      workspace_name = wspace.name
    else
      raise "Unsupported workspace declaration"
    end

    wspace = framework.db.find_workspace(workspace_name)
    raise "Couldn't find workspace #{workspace_name}" if wspace.nil?

    wspace
  end

  # Removes the :workspace or :wspace key from the opts hash.
  #
  # @param [Hash] opts The opts hash passed in from the data request.
  # @return [String] The name of the workspace that was contained in the key.
  def self.delete_opts_workspace(opts)
    wlog("Both :workspace and :wspace were found in opts. Using :workspace.") if opts[:workspace] && opts[:wspace]
    opts.delete(:workspace) || opts.delete(:wspace)
  end
end
end
end
