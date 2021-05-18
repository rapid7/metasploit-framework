module Msf::Ui::Console::CommandDispatcher::Analyze

  def cmd_analyze_help
    print_line "Usage: analyze [OPTIONS] [addr1 addr2 ...]"
    print_line
  end

  def cmd_analyze(*args)
    unless active?
      print_error "Not currently connected to a data service for analysis."
      return []
    end

    host_ranges = []
    print_empty = false

    found_vulns = false
    reported_module = false

    while (arg = args.shift)
      case arg
        when '-h','help'
          cmd_analyze_help
          return
        when '-a', '-v'
          print_empty = true
        when '-p'
          wanted_payloads = args.shift.split(',')
        else
          (arg_host_range(arg, host_ranges))
      end
    end

    host_ranges.push(nil) if host_ranges.empty?

    host_ids = []
    suggested_modules = {}
    each_host_range_chunk(host_ranges) do |host_search|
      next if host_search && host_search.empty?
      eval_hosts_ids = framework.db.hosts(address: host_search).map(&:id)
      if eval_hosts_ids
        eval_hosts_ids.each do |eval_id|
          host_ids.push(eval_id)
        end
      end
    end

    if host_ids.empty?
      print_status("No existing hosts stored to analyze.")
    else

      host_ids.each do |id|
        eval_host = framework.db.hosts(id: id).first
        next unless eval_host
        unless eval_host.vulns
          print_status("No suggestions for #{eval_host.address}.") if  print_empty
          next
        end
        found_vulns = true

        host_result = framework.analyze.host(eval_host, payloads: wanted_payloads)
        found_modules = host_result[:results]
        if found_modules.any?
          reported_module = true
          print_status("Analysis for #{eval_host.address} ->")
          found_modules.each do |res|
            print_status("  " + res.mod.fullname + " - " + res.to_s)
          end

          suggested_modules[eval_host.address] = found_modules
        elsif print_empty
          print_status("No suggestions for #{eval_host.address}.")
        end
      end

      if !print_empty
        if !found_vulns
          if host_ranges.any?
            print_status("No vulnerabilities found for given hosts.")
          else
            print_status("No vulnerabilities found for hosts in this workspace.")
          end
        elsif !reported_module
          print_status("No matching modules found.")
        end
      end
    end

    suggested_modules
  end

  def cmd_analyze_tabs(_str, words)
    return [] unless framework.db.active

    hosts = framework.db.hosts.map(&:address)

    # Limit completion to supplied host if it's the only one
    return [] if words.length > 1 && hosts.length == 1

    hosts
  end

end
