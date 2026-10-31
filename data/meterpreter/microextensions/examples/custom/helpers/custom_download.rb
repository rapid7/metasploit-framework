FILE_PATH_TLV = Rex::Post::Meterpreter::TLV_META_TYPE_STRING | 1202
FILE_MODE_TLV = Rex::Post::Meterpreter::TLV_META_TYPE_STRING | 1203
FILE_CHANNEL = 'stdapi_fs_file'

command 'download', 'Download through the microextension channel helper' do |remote_path, local_path = nil|
  raise ArgumentError, 'Usage: micro run download <remote-path> [local-path]' unless remote_path

  destination = local_path || ::File.basename(remote_path.tr('\\', '/'))
  download(remote_path, destination)
  print_good("Downloaded #{remote_path} to #{destination}")
end

def download(remote_path, local_path)
  channel = open_pool_channel(
    FILE_CHANNEL,
    tlvs: [
      { 'type' => FILE_PATH_TLV, 'value' => remote_path },
      { 'type' => FILE_MODE_TLV, 'value' => 'rb' }
    ]
  )
  ::File.open(local_path, 'wb') do |output|
    loop { output.write(channel.read(65_536)) }
  rescue EOFError
    nil
  ensure
    channel.close
  end
  local_path
end
