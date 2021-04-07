class Msf::Analyze

  def initialize(framework)
    @framework = framework
  end

  def host(eval_host)
    suggested_modules = []

    mrefs, _mports, _mservs = Msf::Modules::Metadata::Cache.instance.all_exploit_maps

    unless eval_host.vulns
      return {}
    end

    vuln_refs = []
    eval_host.vulns.each do |vuln|
      vuln_refs.push(*vuln.refs.map {|r| r.name.upcase})
    end

    # finds all modules that have references matching those found on host vulns with service data
    found_modules = mrefs.values_at(*vuln_refs).compact.reduce(:+)
    found_modules&.each do |fnd_mod|
      creds = @framework.db.creds(port: fnd_mod.rport) if fnd_mod.rport
      r = Result.new(mod: fnd_mod, host: eval_host, available_creds: creds)
      if r.match?
        suggested_modules << r
      end
    end

    {results: suggested_modules}
  end
end
