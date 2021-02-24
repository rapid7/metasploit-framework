module Msf::WebServices::DbImportServlet

  def self.api_path
    '/api/v1/db-import'
  end

  def self.registered(app)
    app.post self.api_path, &db_import
  end

  #######
  private
  #######

  def self.db_import
    lambda do
      warden.authenticate!

      job = lambda do |opts|
        db_filename = File.basename(opts[:filename])
        db_local_path = File.join(Msf::Config.local_directory, db_filename)
        opts[:path] = process_file(opts[:data], db_local_path)
        get_db.import_file(opts)
      end

      exec_report_job(request, &job)
    end
  end

end
