module NmapDataProxy

  def import_nmap_xml_file(args = {})
    begin
      data_service = self.get_data_service
      add_opts_workspace(args)
      data_service.import_nmap_xml_file(args)
    rescue => e
      self.log_error(e, "Problem importing Nmap XML file")
    end
  end
end