require 'fileutils'
# FileManager
module Msf::DBManager::FileManager
  def list_local_path(path)
    # Enumerate each item...
    tbl = []
    files = Dir.entries(path)
    files.each do |file|
      file_path = File.join(path, file)
      stat = File.stat(file_path)
      row = {
        name: file.force_encoding('UTF-8'),
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
end
