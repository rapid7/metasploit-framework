
folder_to_count = "C:\Users\rahul\Documents\git\metasploit-framework-1\modules\post\windows\*"  # You should change this
begin
  file_count = Dir.glob(File.join(folder_to_count, '**', '*')).select { |file| File.file?(file) }.count
  puts file_count
rescue
  puts "ERROR: The number of files could not be obtained"
  # typically occurs if folder_to_count does not exist
end