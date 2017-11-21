module NmapServlet

  def self.api_path
    '/api/1/msf/nmap'
  end

  def self.registered(app)
    app.post NmapServlet.api_path, &import_nmap_xml_file
  end

  #######
  private
  #######

  def self.import_nmap_xml_file
    lambda {

      job = lambda { |opts|
        nmap_file = opts[:filename].split('/').last
        nmap_file_path = File.join(Msf::Config.local_directory, nmap_file)
        opts[:filename] = process_file(opts[:data], nmap_file_path)
        get_db().import_nmap_xml_file(opts)
      }
      exec_report_job(request, &job)
    }
  end
end