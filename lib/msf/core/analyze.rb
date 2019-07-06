class Msf::Analyze

  def initialize(framework)
    @framework = framework
  end

  def host(eval_host)
    suggested_modules = {}

    mrefs, _mports, _mservs = Msf::Modules::Metadata::Cache.instance.all_remote_exploit_maps

    unless eval_host.vulns
      return {}
    end

    vuln_refs = []
    eval_host.vulns.each do |vuln|
      next if vuln.service.nil?
      vuln_refs.push(*vuln.refs)
    end

    # finds all modules that have references matching those found on host vulns with service data
    found_modules = mrefs.values_at(*(vuln_refs.map { |x| x.name.upcase } & mrefs.keys)).map { |x| x.values }.flatten.uniq
    found_modules.each do |fnd_mod|
      # next if exploit_filter_by_service(fnd_mod, vuln.service)
      next unless exploit_matches_host_os(fnd_mod, eval_host)
    end

    suggested_modules[:modules] = found_modules

    suggested_modules
  end


  private

  # Tests for various service conditions by comparing the module's fullname (which
  # is basically a pathname) to the intended target service record. The service.info
  # column is tested against a regex in most/all cases and "false" is returned in the
  # event of a match between an incompatible module and service fingerprint.
  def exploit_filter_by_service(mod, serv)

    # Filter out Unix vs Windows exploits for SMB services
    return true if (mod.fullname =~ /\/samba/ and serv.info.to_s =~ /windows/i)
    return true if (mod.fullname =~ /\/windows/ and serv.info.to_s =~ /samba|unix|vxworks|qnx|netware/i)
    return true if (mod.fullname =~ /\/netware/ and serv.info.to_s =~ /samba|unix|vxworks|qnx/i)

    # Filter out IIS exploits for non-Microsoft services
    return true if (mod.fullname =~ /\/iis\/|\/isapi\// and (serv.info.to_s !~ /microsoft|asp/i))

    # Filter out Apache exploits for non-Apache services
    return true if (mod.fullname =~ /\/apache/ and serv.info.to_s !~ /apache|ibm/i)

    false
  end

  # Determines if an exploit (mod, an instantiated module) is suitable for the host (host)
  # defined operating system. Returns true if the host.os isn't defined, if the module's target
  # OS isn't defined, if the module's OS is "unix" and the host's OS is not "windows," or
  # if the module's target is "php." Or, of course, in the event the host.os actually matches.
  # This is a fail-open gate; if there's a doubt, assume the module will work on this target.
  def exploit_matches_host_os(mod, host)
    hos = host.os_name
    return true if hos.nil? || hos.empty?

    set = mod.platform.split(',').map{ |x| x.downcase }
    return true if set.empty?

    # Special cases
    return true if set.include?("unix") and hos !~ /windows/i

    if set.include?("unix")
      # Skip archaic old HPUX bugs if we have a solid match against another OS
      return false if set.include?("hpux") and mod.refname.index("hpux") and hos =~ /linux|irix|solaris|aix|bsd/i
      # Skip AIX bugs if we have a solid match against another OS
      return false if set.include?("aix") and mod.refname.index("aix") and hos =~ /linux|irix|solaris|hpux|bsd/i
      # Skip IRIX bugs if we have a solid match against another OS
      return false if set.include?("irix") and mod.refname.index("irix") and hos =~ /linux|solaris|hpux|aix|bsd/i
    end

    return true if set.include?("php")

    set.each do |mos|
      return true if hos.downcase.index(mos)
    end

    false
  end
end
