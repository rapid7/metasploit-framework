#
# Standard Library
#

require 'fileutils'
module FileServlet
  def self.api_path
    '/api/v1/files'
  end

  def self.api_path_for_file
    "#{FileServlet.api_path}/file"
  end

  def self.api_path_for_dir
    "#{FileServlet.api_path}/dir"
  end

  def self.registered(app)
    app.get FileServlet.api_path_for_file, &file_download
    app.post FileServlet.api_path_for_file, &file_upload
    app.put FileServlet.api_path_for_file, &file_rename
    app.delete FileServlet.api_path_for_file, &file_delete

    app.get FileServlet.api_path_for_dir, &dir_entries
    app.post FileServlet.api_path_for_dir, &dir_mkdir
    app.put FileServlet.api_path_for_dir, &dir_rename
    app.delete FileServlet.api_path_for_dir, &dir_delete
  end
  #######

  #######
  # file
  def self.file_download
    lambda {
      warden.authenticate!
      sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
      opts_path = sanitized_params[:path] || ''
      path = File.join(Msf::Config.rest_files_directory, opts_path)
      if safe_expand_path?(path) && File.exist?(path) && !File.directory?(path)
        send_file(path, buffer_size: 4096, stream: true)
      else
        result = { message: 'No such file' }
        set_json_data_response(response: result)
      end
    }
  end

  def self.file_upload
    lambda {
      warden.authenticate!
      sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
      if sanitized_params[:file]
        opts_path = sanitized_params[:path] || ''
        path = File.join(Msf::Config.rest_files_directory, opts_path)
        temp_path = sanitized_params[:file][:tempfile].path
        if safe_expand_path?(path) && !File.exist?(path)
          FileUtils.mkdir_p(File.dirname(path))
          FileUtils.cp_r(temp_path, path)
          result = { path: path }
        else
          result = { message: 'The file already exists' }
        end
        FileUtils.rm_rf(temp_path) if File.exist?(temp_path)
      else
        result = { message: 'Please upload a file' }
      end
      set_json_data_response(response: result)
    }
  end

  def self.file_delete
    lambda {
      warden.authenticate!
      opts = parse_json_request(request, true)
      opts_path = opts[:path] || ''
      path = File.join(Msf::Config.rest_files_directory, opts_path)
      if !rest_files_directory?(path) && !File.directory?(path) && safe_expand_path?(path)
        FileUtils.rm_rf(path)
        result = { path: path }
      else
        result = { message: 'No such file' }
      end
      set_json_data_response(response: result)
    }
  end

  def self.file_rename
    lambda {
      warden.authenticate!
      opts = parse_json_request(request, true)
      opts_path = opts[:path] || ''
      opts_new_path = opts[:new_path] || ''
      path = File.join(Msf::Config.rest_files_directory, opts_path)
      new_path = File.join(Msf::Config.rest_files_directory, opts_new_path)
      if (!File.directory?(path) && safe_expand_path?(path)) && File.exist?(path) \
        && (!File.directory?(new_path) && safe_expand_path?(new_path))
        FileUtils.mv(path, new_path)
        result = { path: new_path }
      else
        result = { message: 'No such file' }
      end
      set_json_data_response(response: result)
    }
  end

  # dir
  def self.dir_entries
    lambda {
      warden.authenticate!
      sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
      opts_path = sanitized_params[:path] || ''
      path = File.join(Msf::Config.rest_files_directory, opts_path)
      if safe_expand_path?(path) && File.directory?(path)
        result = list_local_path(path)
      else
        result = { message: 'No such directory' }
      end
      set_json_data_response(response: result)
    }
  end

  def self.dir_mkdir
    lambda {
      warden.authenticate!
      opts = parse_json_request(request, true)
      opts_path = opts[:path] || ''
      path = File.join(Msf::Config.rest_files_directory, opts_path)
      if safe_expand_path?(path)
        FileUtils.mkdir_p(path)
        result = { path: path }
      else
        result = { message: 'Failed to create folder' }
      end
      set_json_data_response(response: result)
    }
  end

  def self.dir_delete
    lambda {
      warden.authenticate!
      opts = parse_json_request(request, true)
      opts_path = opts[:path] || ''
      path = File.join(Msf::Config.rest_files_directory, opts_path)
      if !rest_files_directory?(path) && safe_expand_path?(path) && File.directory?(path)
        FileUtils.rm_rf(path)
        result = { path: path }
      else
        result = { message: 'No such directory' }
      end
      set_json_data_response(response: result)
    }
  end

  def self.dir_rename
    lambda {
      warden.authenticate!
      opts = parse_json_request(request, true)
      opts_path = opts[:path] || ''
      opts_new_path = opts[:new_path] || ''
      path = File.join(Msf::Config.rest_files_directory, opts_path)
      new_path = File.join(Msf::Config.rest_files_directory, opts_new_path)
      if (!rest_files_directory?(path) && safe_expand_path?(path) && File.directory?(path)) \
        && (!rest_files_directory?(new_path) && safe_expand_path?(new_path))
        FileUtils.mv(path, new_path)
        result = { path: new_path }
      else
        result = { message: 'No such directory' }
      end
      set_json_data_response(response: result)
    }
  end
end

def list_local_path(path)
  # Enumerate each item...
  tbl = []
  files = Dir.entries(path)
  files.each do |file|
    file_path = File.join(path, file)
    stat = File.stat(file_path)
    row = {
      name: file,
      type: stat.ftype || '',
      size: stat.size ? stat.size.to_s : '',
      last_modified: stat.mtime || ''
    }
    next unless file != '.' && file != '..'

    tbl << row
  end
  return tbl
end

def safe_expand_path?(path)
  current_directory = File.expand_path(Msf::Config.rest_files_directory) + File::SEPARATOR
  tested_path = File.expand_path(path) + File::SEPARATOR
  tested_path.starts_with?(current_directory)
end

def rest_files_directory?(path)
  tested_path = File.expand_path(path) + File::SEPARATOR
  current_directory = File.expand_path(Msf::Config.rest_files_directory) + File::SEPARATOR
  tested_path == current_directory
end
