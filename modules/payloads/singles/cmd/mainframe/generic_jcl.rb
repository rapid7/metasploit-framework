##
# This is a prototype JCL command payload for z/OS - mainframe.
#   It submits the IEFBR14 standard z/OS program, which does nothing
#   but complete successfully and return code 0.
#
#   See http://www.ibm.com/support/knowledgecenter/SSLTBW_2.1.0/com.ibm.zos.v2r1.ieab500/hpropr.htm?lang=en
#   for more information on IEFBR14
##

require 'msf/core'
require 'msf/core/handler/find_shell'
require 'msf/base/sessions/mainframe_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

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
        }
      )
    )
  end

  ##
  # Construct the paload
  ##
  def generate
    super + command_string
  end

  ##
  # Build the command string for JCL submission
  ##
  def command_string
    "//DUMMY  JOB (MFUSER),'dummy job',\n" \
    "//   NOTIFY=&SYSUID,\n" \
    "//   MSGCLASS=H,\n" \
    "//   MSGLEVEL=(1,1),\n" \
    "//   REGION=0M\n" \
    "//   EXEC PGM=IEFBR14\n"
  end
end
