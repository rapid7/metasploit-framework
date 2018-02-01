module NmapDataProxy

  def import_nmap_xml_file(args = {})
    begin
      data_service = self.get_data_service()
      data_service.import_nmap_xml_file(args)
    rescue Exception => e
      elog "Call to #{data_service.class}#import_nmap_xml_file threw exception: #{e.message}"
    end
  end
end