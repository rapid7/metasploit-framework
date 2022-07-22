# -*- coding: binary -*-

module Msf::Auxiliary::ManageEngineXnode::Action
  # Returns an Xnode authentication request hash
  #
  # @param user [String] Username
  # @param pass [String] Password
  # @return [Hash] Xnode authentication request 
  def action_authenticate(user,pass)
    {
      "username" => user,
      "password" => pass,
      "action" => "session:/authenticate"
    }
  end

  # Returns an Xnode health status request hash
  #
  # @return [Hash] Xnode health status request 
  def action_admin_health
    {
      "action" => "admin:/health",
      "de_health" => true,
      "request_id" => 1,  
    }
  end

  # Returns an Xnode info request hash
  #
  # @return [Hash] Xnode info request 
  def action_xnode_info
    {
      "action" => "admin:/xnode_info",
      "request_id" => 1,
    }
  end

  # Returns an Xnode DataRespository Search request hash
  #
  # @param repo_name [String] Name of the DataRespository to query
  # @param fields [Array] data respository fields (columns) to dump
  # @param custom_query [Hash] A hash containing a custom query to merge with the query hash
  # @return [Hash] Xnode data respository search request
  def action_dr_search(repo_name, fields=nil, custom_query=nil)
    time_gen_from = rand(500000000..1000000000) # generate random Unix timestamp somewhere between 1985 - 2001, used below as the "from" date, to ensure we get all data we want
    time_gen_to = Time.now.to_i + 100000 # take the current time and add 100,000 seconds (a little over a day) to rule out any issues arising from time zone differences
    query = {
      "action" => 'dr:/dr_search',
      "dr_name_list" => [repo_name],
      "query" => "TIME_GENERATED:[#{time_gen_from} TO #{time_gen_to}]", # this uses Unix Timestamp format
      "request_id" => 1,
    }

    # pass the fields (columns) to dump if possible
    if fields
      query['select_fields'] = fields
    end

    if custom_query
      query = query.merge(custom_query)
    end

    query
  end
end
