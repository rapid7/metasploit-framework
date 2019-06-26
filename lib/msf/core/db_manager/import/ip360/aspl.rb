require 'rex/parser/ip360_aspl_xml'

module Msf::DBManager::Import::IP360::ASPL
  #
  # Import IP360's ASPL database
  #
  def import_ip360_aspl_xml(args={}, &block)
    data = args[:data]
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    if not data.index("<ontology")
      raise Msf::DBImportError.new("The ASPL file does not appear to be valid or may still be compressed")
    end

    base = ::File.join(Msf::Config.config_directory, "data", "ncircle")
    ::FileUtils.mkdir_p(base)
    ::File.open(::File.join(base, "ip360.aspl"), "wb") do |fd|
      fd.write(data)
    end
    yield(:notice, "Saved the IP360 ASPL database to #{base}...")
  end
end
