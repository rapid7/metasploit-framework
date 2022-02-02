class Msf::Analyze

  def initialize(framework)
    @framework = framework
  end

  def host(eval_host, payloads: nil)
    unless eval_host.vulns
      return {}
    end

    # Group related vulns
    vuln_families = group_vulns(eval_host.vulns)

    # finds all modules that have references matching those found on host vulns with service data
    suggested_modules = suggest_modules_for_vulns(eval_host, vuln_families, payloads: payloads)

    {results: suggested_modules}
  end

  private

  def group_vulns(vulns)
    return [] if vulns.empty?

    vulns = vulns.map do |vuln|
      [vuln, Set.new(vuln.refs.map {|r| r.name.upcase})]
    end
    grouped_vulns = Hash.new

    vulns.each_index do |ii|
      vuln, refs = vulns[ii]
      grouped_vulns[vuln] ||= [Set.new, Set.new]
      grouped_vulns[vuln][0] << vuln
      grouped_vulns[vuln][1].merge(refs)

      vulns[(ii+1)..-1].each do |candidate_match, candidate_refs|
        # TODO: measure if sorting the refs ahead of time and doing a O(n + m)
        # walk here is faster
        if candidate_refs.intersect? refs
          if grouped_vulns[candidate_match]
            # For merging two different transitive sets that overlap, we need
            # to merge the individual grouping elements and then use those
            # cells inside both the grouping arrays so that all the
            # already-visited vulns are rolled into the big new set
            grouped_vulns[candidate_match][0] = grouped_vulns[candidate_match][0].merge(grouped_vulns[vuln][0])
            grouped_vulns[candidate_match][1] = grouped_vulns[candidate_match][1].merge(grouped_vulns[vuln][1])
            grouped_vulns[vuln][0] = grouped_vulns[candidate_match][0]
            grouped_vulns[vuln][1] = grouped_vulns[candidate_match][1]
          else
            # Whoever was initialized first has the canonical set
            grouped_vulns[candidate_match] = grouped_vulns[vuln]
          end
        end
      end
    end

    vuln_families = grouped_vulns.values
    vuln_families.uniq!
    vuln_families
  end

  def suggest_modules_for_vulns(eval_host, vuln_families, payloads: nil)
    mrefs, _mports, _mservs = Msf::Modules::Metadata::Cache.instance.all_exploit_maps
    suggested_modules = []

    evaluated_module_targets = Set.new
    to_evaluate_with_defaults = Array.new
    vuln_families.each do |vulns, refs|
      found_modules = mrefs.values_at(*refs).compact.reduce(:+)
      next unless found_modules

      services = vulns.map(&:service).compact
      found_modules.each do |fnd_mod|
        if services.any?
          services.each do |svc|
            port = svc.port
            next if evaluated_module_targets.include?([fnd_mod, port])

            creds = @framework.db.creds(svcs: [svc.name])
            r = Result.new(mod: fnd_mod, host: eval_host, datastore: {'rport': port},
                           available_creds: creds, payloads: payloads, framework: @framework)
            if r.match?
              suggested_modules << r.evaluate
            end
            evaluated_module_targets << [fnd_mod, port]
          end
        else
          # Only have the default port to go off of, at least for this vuln,
          # prefer using the service data if available on a different vuln
          # entry
          port = fnd_mod.rport
          to_evaluate_with_defaults << [fnd_mod, port]
        end
      end
    end

    to_evaluate_with_defaults.each do |fnd_mod, port|
      next if evaluated_module_targets.include?([fnd_mod, port])

      creds = @framework.db.creds(port: port) if port
      r = Result.new(mod: fnd_mod, host: eval_host, datastore: {'rport': port},
                     available_creds: creds, payloads: payloads, framework: @framework)

      if r.match?
        suggested_modules << r.evaluate
      end
      evaluated_module_targets << [fnd_mod, port]
    end

    suggested_modules
  end
end
