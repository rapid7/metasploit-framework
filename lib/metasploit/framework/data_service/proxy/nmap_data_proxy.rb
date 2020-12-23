module NmapDataProxy

  def import_nmap_xml_file(args = {})
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(args)
        data_service.import_nmap_xml_file(args)
      end
    rescue => e
      self.log_error(e, "Problem importing Nmap XML file")
    end
  end
end