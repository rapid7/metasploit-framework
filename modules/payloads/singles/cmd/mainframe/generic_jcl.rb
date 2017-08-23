##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# This is a prototype JCL command payload for z/OS - mainframe.
#   It submits the IEFBR14 standard z/OS program, which does nothing
#   but complete successfully and return code 0.
#
#   See http://www.ibm.com/support/knowledgecenter/SSLTBW_2.1.0/com.ibm.zos.v2r1.ieab500/hpropr.htm?lang=en
#   for more information on IEFBR14
##

require 'msf/core/handler/find_shell'
require 'msf/base/sessions/mainframe_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule
  CachedSize = 150
  include Msf::Payload::Single
  include Msf::Payload::Mainframe
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
                     'Name'          => 'Generic JCL Test for Mainframe Exploits',
                     'Description'   => 'Provide JCL which can be used to submit
                        a job to JES2 on z/OS which will exit and return 0.  This
                        can be used as a template for other JCL based payloads',
                     'Author'        => 'Bigendian Smalls',
                     'License'       => MSF_LICENSE,
                     'Platform'      => 'mainframe',
                     'Arch'          => ARCH_CMD,
                     'Handler'       => Msf::Handler::None,
                     'Session'       => Msf::Sessions::MainframeShell,
                     'PayloadType'   => 'cmd',
                     'RequiredCmd'   => 'jcl',
                     'Payload'       =>
      {
        'Offsets' => {},
        'Payload' => ''
      }))
    register_options(
      [
        OptString.new('ACTNUM', [true, "Accounting info for JCL JOB card", "MSFUSER-ACCTING-INFO"]),
        OptString.new('PGMNAME', [true, "Programmer name for JCL JOB card", "programmer name"]),
        OptString.new('JCLASS', [true, "Job Class for JCL JOB card", "A"]),
        OptString.new('NOTIFY', [false, "Notify User for JCL JOB card", ""]),
        OptString.new('MSGCLASS', [true, "Message Class for JCL JOB card", "Z"]),
        OptString.new('MSGLEVEL', [true, "Message Level for JCL JOB card", "(0,0)"])
      ],
      self.class
    )
    register_advanced_options(
      [
        OptBool.new('NTFYUSR', [true, "Include NOTIFY Parm?", false]),
        OptString.new('JOBNAME', [true, "Job name for JCL JOB card", "DUMMY"])
      ],
      self.class
    )
  end

  ##
  # Construct Payload
  ##
  def generate
    super + command_string
  end

  ##
  # Setup replacement vars from options if need be
  ##
  def command_string
    jcl_jobcard +
      "//   EXEC PGM=IEFBR14\n"
  end
end
