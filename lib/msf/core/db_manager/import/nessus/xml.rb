module Msf::DBManager::Import::Nessus::XML
  #
  # Import Nessus XML v1 and v2 output
  #
  # Old versions of openvas exported this as well
  #
  def import_nessus_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end

    if data.index("NessusClientData_v2")
      import_nessus_xml_v2(args.merge(:data => data))
    else
      import_nessus_xml(args.merge(:data => data))
    end
  end
end
