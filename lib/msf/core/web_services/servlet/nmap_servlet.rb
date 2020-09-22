module Msf::WebServices::NmapServlet

  def self.api_path
    '/api/v1/nmaps'
  end

  def self.registered(app)
    app.post self.api_path, &import_nmap_xml_file
  end

  #######
  private
  #######

  def self.import_nmap_xml_file
    lambda {
      warden.authenticate!

      job = lambda { |opts|
        nmap_file = File.basename(opts[:filename])
        nmap_file_path = File.join(Msf::Config.local_directory, nmap_file)
        opts[:filename] = process_file(opts[:data], nmap_file_path)
        get_db.import_nmap_xml_file(opts)
      }
      exec_report_job(request, &job)
    }
  end
end