module NmapDataProxy

  def import_nmap_xml_file(args = {})
    begin
      data_service = self.get_data_service()
      data_service.import_nmap_xml_file(args)
    rescue Exception => e
      self.log_error(e, "Problem importing Nmap XML file")
    end
  end
end