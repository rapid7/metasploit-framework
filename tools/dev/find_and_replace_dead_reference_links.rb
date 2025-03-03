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

# Loads JSON data from the specified file.
# @param file_path [String] the path to the JSON file to load.
# @return [Array] parsed JSON data.
# @raise [Errno::ENOENT] if the file cannot be found.
# @raise [JSON::ParserError] if the JSON is malformed.
def load_json(file_path)
  JSON.parse(File.read(file_path))
end

# Replaces the original URLs with archived snapshots in the content of files.
# This method processes each entry in the provided data, and if a valid
# archived snapshot is available, it replaces the URL in the corresponding file.
# @param data [Array] the array of data containing URL and archived_snapshot pairs.
# @return [void]
def replace_links_in_files(data)
  data.each_with_index do |entry, index|
    puts "Processing entry #{index + 1}: #{entry['url']} -> #{entry['archived_snapshot']}"

    url = entry['url'].sub(/^URL-/, '')
    path = entry['path']
    archived_snapshot = entry['archived_snapshot']

    # Skip entries with no archived version or errors fetching the snapshot
    if archived_snapshot == 'No archived version found' || archived_snapshot.nil? || archived_snapshot.start_with?('Error fetching Wayback')
      puts "Skipping entry #{index + 1} because no archived version is available or there was an error fetching it."
      next
    end

    # Construct full file path and check if file exists
    full_path = File.join(Dir.pwd, path)

    if File.exist?(full_path)
      file_content = File.read(full_path)

      # Replace the original URL with the archived snapshot
      updated_content = file_content.gsub(url, archived_snapshot)

      # Write changes back to the file if any replacements were made
      if file_content != updated_content
        File.open(full_path, 'w') { |file| file.write(updated_content) }
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
  # Load the JSON data from the file 'url_check_results.json'
  json_data = load_json('url_check_results.json')

  # Replace the URLs in files based on the loaded data
  replace_links_in_files(json_data)
rescue StandardError => e
  # Handle errors gracefully and provide meaningful feedback
  puts "An error occurred: #{e.message}"
end
