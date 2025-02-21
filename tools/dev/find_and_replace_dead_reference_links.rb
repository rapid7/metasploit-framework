##
#
# tools/dev/detect_dead_reference_links.rb must be run before this script as it will
# create the url_check_results.json file that is used to run the script.
#
# Usage: ruby tools/dev/find_and_replace_dead_reference_links.rb -f url_check_results.json
#
##

require 'json'
require 'fileutils'

def load_json(file_path)
  JSON.parse(File.read(file_path))
end

def replace_links_in_files(data)
  data.each_with_index do |entry, index|
    puts "Processing entry #{index + 1}: #{entry['url']} -> #{entry['archived_snapshot']}"

    url = entry["url"].sub(/^URL-/, '')
    path = entry["path"]
    archived_snapshot = entry["archived_snapshot"]

    if archived_snapshot == "No archived version found" || archived_snapshot.nil?
      puts "Skipping entry #{index + 1} because no archived version is available."
      next
    end

    full_path = File.join(Dir.pwd, path)

    if File.exist?(full_path)
      file_content = File.read(full_path)

      updated_content = file_content.gsub(url, archived_snapshot)

      if file_content != updated_content
        File.open(full_path, "w") { |file| file.write(updated_content) }
        puts "Replaced URL in file: #{full_path}"
      else
        puts "No change needed for file: #{full_path}"
      end
    else
      puts "File not found: #{full_path}"
    end
  end
end

begin
  json_data = load_json('url_check_results.json') # Change this to the actual JSON file path
  replace_links_in_files(json_data)
rescue => e
  puts "An error occurred: #{e.message}"
end
