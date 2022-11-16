# -*- coding: binary -*-

module Msf::Exploit::Remote::HTTP::Webmin::Check
  # performs a webmin version check
  #
  # @param high_inclusive_version [String] The high inclusive version (highest vulenrable version).
  # @return [CheckCode] A CheckCode based on the version passed into the method
  def webmin_check(low_version, high_inclusive_version)
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    )

    return Msf::Exploit::CheckCode::Unknown("#{peer} - Could not connect to web service - no response") unless res

    if res.body.include?('This web server is running in SSL mode.')
      return Msf::Exploit::CheckCode::Unknown("#{peer} - Please enable the SSL option to proceed")
    end

    version = res.headers['Server'].to_s.scan(%r{MiniServ/([\d.]+)}).flatten.first

    return Msf::Exploit::CheckCode::Unknown("#{peer} - Webmin version not detected") unless version

    version = Rex::Version.new(version)

    vprint_status("Webmin #{version} detected")

    unless version <= Rex::Version.new(high_inclusive_version) && version >= Rex::Version.new(low_version)
      return Msf::Exploit::CheckCode::Safe("#{peer} - Webmin #{version} is not a supported target")
    end

    vprint_good("Webmin #{version} is a supported target")

    Msf::Exploit::CheckCode::Appears
  rescue ::Rex::ConnectionError
    return Msf::Exploit::CheckCode::Unknown("#{peer} - Could not connect to web service")
  end
end
