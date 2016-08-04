# -*- coding: binary -*-
require 'msf/core'

###
# This class is here to implement advanced features for mainframe based
# payloads. Mainframe payloads are expected to include this module if
# they want to support these features.
###
module Msf::Payload::Mainframe
  def initialize(info = {})
    super(info)
  end

  ##
  # Returns a list of compatible encoders based on mainframe architecture
  # most will not work because of the different architecture
  # an XOR-based encoder will be defined soon
  ##
  def compatible_encoders
    encoders2 = ['/generic\/none/', 'none']
    encoders2
  end

  ###
  # This method is here to implement advanced features for cmd:jcl based
  # payloads.  Common to all are the JCL Job Card, and its options which
  # are defined here. It is optional for other mainframe payloads.
  ###
  def jcl_jobcard
    # format paramaters with basic constraints
    # see http://www.ibm.com/support/knowledgecenter/SSLTBW_2.1.0/
    #     com.ibm.zos.v2r1.ieab600/iea3b6_Parameter_field8.htm
    #
    jobname = format('%1.8s', datastore['JOBNAME']).strip.upcase
    actnum  = format('%1.60s', datastore['ACTNUM']).strip.upcase
    pgmname = format('%1.20s', datastore['PGMNAME']).strip
    jclass  = format('%1.1s', datastore['JCLASS']).strip.upcase
    notify  = format('%1.8s', datastore['NOTIFY']).strip.upcase
    notify  = if !notify.empty? && datastore['NTFYUSR']
                "//   NOTIFY=#{notify}, \n"
              else
                ""
              end
    msgclass = format('%1.1s', datastore['MSGCLASS']).strip.upcase
    msglevel = format('%5.5s', datastore['MSGLEVEL']).strip

    # build payload
    "//#{jobname} JOB "            \
    "(#{actnum}),\n"               \
    "//   '#{pgmname}',\n"         \
    "//   CLASS=#{jclass},\n"      \
    "#{notify}"                    \
    "//   MSGCLASS=#{msgclass},\n" \
    "//   MSGLEVEL=#{msglevel},\n" \
    "//   REGION=0M \n"
  end
end
