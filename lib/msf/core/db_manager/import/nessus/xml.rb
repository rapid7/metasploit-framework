module Msf::DBManager::Import::Nessus::XML
  autoload :V1, 'msf/core/db_manager/import/nessus/xml/v1'
  autoload :V2, 'msf/core/db_manager/import/nessus/xml/v2'

  include Msf::DBManager::Import::Nessus::XML::V1
  include Msf::DBManager::Import::Nessus::XML::V2

  #
  # Import Nessus XML v1 and v2 output
  #
  # Old versions of openvas exported this as well
  #
  def import_nessus_xml_file(args={})
    filename = args[:filename]

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
