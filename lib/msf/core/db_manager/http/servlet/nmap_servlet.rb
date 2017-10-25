module nmapServlet

  def self.api_path
    '/api/1/msf/nmap'
  end

  def self.registered(app)
    app.post nmapServlet.api_path, &import_nmap_xml_file
  end

  #######
  private
  #######

  def self.import_nmap_xml_file
    lambda {

      job = lambda { |opts|
        get_db().import_nmap_xml_file(opts)
      }
      exec_report_job(request, &job)
    }
  end
end