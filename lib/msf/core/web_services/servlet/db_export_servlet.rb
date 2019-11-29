module DbExportServlet

  def self.api_path
    '/api/v1/db-export'
  end

  def self.registered(app)
    app.get DbExportServlet.api_path, &get_db_export
  end

  #######
  private
  #######

  def self.get_db_export
    lambda {
      warden.authenticate!
      begin
        opts = params.symbolize_keys
	      opts[:path] = File.join(Msf::Config.local_directory, "#{File.basename(opts[:path])}-#{SecureRandom.hex}")

        output_file = get_db.run_db_export(opts)

        encoded_file = Base64.urlsafe_encode64(File.read(File.expand_path(output_file)))
        response = {}
        response[:db_export_file] = encoded_file
        set_json_data_response(response: response)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error exporting the database:', code: 500)
      ensure
        # Ensure the temporary file gets cleaned up
        File.delete(opts[:path])
      end
    }
  end
end
