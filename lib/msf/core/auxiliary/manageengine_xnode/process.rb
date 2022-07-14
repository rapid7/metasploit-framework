# -*- coding: binary -*-

module Msf::Auxiliary::ManageengineXnode::Process
  include Msf::Auxiliary::ManageengineXnode::Action
  include Msf::Auxiliary::ManageengineXnode::Interact
  # Processes the obtained server response from a ManageEngine Xnode data repository search request
  #
  # @param res [Hash] JSON-parsed response from the Xnode server. This should be a Hash.
  # @param res_code [Integer] Response code received during the previos get_response call
  # @param repo_name [String] Name of the data repository that was queried
  # @param fields [Array] names of the data repository fields (columns) that were dumped
  # @param mode [String] the type of query that was performed: standard, total_hits, aggr_min or aggr_max
  # @return [Array, Integer] Array containing the parsed query results if parsing succeeds, error code otherwise
  def process_dr_search(res, res_code, repo_name, fields=nil, mode='standard')
    if res_code == 1
      print_error("Received unexpected reply when trying to dump table #{repo_name}: #{res}")
      print_warning("The target may not be exploitable.")
      return 1
    end

    response = res['response']

    unless response.include?('search_result') && response.include?('total_hits')
      if response.include?('error_msg')
        error_msg = response['error_msg']
        if /DataRepository for '[a-zA-Z]+' not found!/ =~ error_msg
          print_status("The data repository #{repo_name} is not available on the target.")
          return 1
        end

        print_error("Received error message: #{error_msg}")
        return 1
      end

      print_error("Received unexpected query response: #{response}")
      return 1
    end

    case mode
    when 'total_hits'
      # try to grab the total hits
      total_hits = response['total_hits']
      unless total_hits && total_hits.is_a?(Integer)
        print_error("Received unexpected reply when trying to obtain the number of total hits for table #{repo_name}.")
        print_warning("The target may not be exploitable.")
        return 1
      end

      if total_hits == 0
        print_status("Data repository #{repo_name} is empty.")
        return 1
      end

      return total_hits.to_s # return this as a string to the calling method can distinguish it from an error code
    when 'aggr_min', 'aggr_max'
      aggr_type = mode.split("_")[1]
      unless response.include?('aggr_result') && response['aggr_result'].is_a?(Hash) && response['aggr_result'].include?(aggr_type)
        print_error("Received unexpected reply when trying to obtain #{aggr_type} aggregrate value for the UNIQUE_ID field.")
        return 1
      end

      return response['aggr_result'][aggr_type]
    when 'standard'
      search_result = response['search_result']
      if search_result.empty?
        vprint_status("The query returned no records.")
        return 1
      end

      unless search_result.is_a? Array
        print_error("Received unexpected query response: #{response}")
        return 1
      end

      return search_result if fields.nil?
      
      process_results(search_result, repo_name, fields)
    end
  end

  # Processes the search_result received from the Xnode server. If the fields parameter is provided, received values are mapped to known field (column) names.
  #
  # @param search_result [Array] nested Array containing the data repository rows and their values
  # @param repo_name [String] Name of the data respository that was queried
  # @param fields [Array] data repository fields (columns) that were dumped, used for mapping the search_result values to field names
  # @return [Array] Array containing the query results if the provided paramters are correct, empty Array otherwise
  def process_results(search_result, repo_name, fields)
    results = []
    non_empty_val_ct = 0 # used to check the search results contains at least one non_empty value 
    # map the search returned values to the specified fields
    search_result.each do |row|
      row_data = {}
      row.each_with_index do |val, index|
        non_empty_val_ct += 1 unless val.blank?
        column_name = fields[index]
        row_data[column_name] = val
      end 
      results << row_data
    end

    if non_empty_val_ct == 0
      results = []
    end

    results
  end
end
