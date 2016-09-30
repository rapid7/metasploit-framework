# -*- coding: binary -*-
module Rex
module Proto
module IAX2


IAX2_DEFAULT_PORT = 4569


IAX_TYPE_VOICE   = 2
IAX_TYPE_CONTROL = 4
IAX_TYPE_IAX     = 6
IAX_TYPE_DTMF_BEGIN = 1
IAX_TYPE_DTMF_END   = 12

IAX_CTRL_HANGUP   = 1
IAX_CTRL_RINGING  = 3
IAX_CTRL_ANSWER   = 4
IAX_CTRL_BUSY     = 5
IAX_CTRL_PROGRESS = 14
IAX_CTRL_PROCEED  = 15

=begin
   +-------------+---------------+-------------------------------------+
   | VALUE       | Name          | Description                         |
   +-------------+---------------+-------------------------------------+
   | 0x01        | Hangup        | The call has been hungup at the     |
   |             |               | remote end                          |
   |             |               |                                     |
   | 0x02        | Reserved      | Reserved for future use             |
   |             |               |                                     |
   | 0x03        | Ringing       | Remote end is ringing (ring-back)   |
   |             |               |                                     |
   | 0x04        | Answer        | Remote end has answered             |
   |             |               |                                     |
   | 0x05        | Busy          | Remote end is busy                  |
   |             |               |                                     |
   | 0x06        | Reserved      | Reserved for future use             |
   |             |               |                                     |
   | 0x07        | Reserved      | Reserved for future use             |
   |             |               |                                     |
   | 0x08        | Congestion    | The call is congested               |
   |             |               |                                     |
   | 0x09        | Flash Hook    | Flash hook                          |
   |             |               |                                     |
   | 0x0a        | Reserved      | Reserved for future use             |
   |             |               |                                     |
   | 0x0b        | Option        | Device-specific options are being   |
   |             |               | transmitted                         |
   |             |               |                                     |
   | 0x0c        | Key Radio     | Key Radio                           |
   |             |               |                                     |
   | 0x0d        | Unkey Radio   | Unkey Radio                         |
   |             |               |                                     |
   | 0x0e        | Call Progress | Call is in progress                 |
   |             |               |                                     |
   | 0x0f        | Call          | Call is proceeding                  |
   |             | Proceeding    |                                     |
   |             |               |                                     |
   | 0x10        | Hold          | Call is placed on hold              |
   |             |               |                                     |
   | 0x11        | Unhold        | Call is taken off hold              |
   +-------------+---------------+-------------------------------------+
=end


IAX_SUBTYPE_NEW     = 1
IAX_SUBTYPE_PING    = 2
IAX_SUBTYPE_PONG    = 3
IAX_SUBTYPE_ANSWER  = 4
IAX_SUBTYPE_ACK     = 4
IAX_SUBTYPE_HANGUP  = 5
IAX_SUBTYPE_REJECT  = 6
IAX_SUBTYPE_ACCEPT  = 7
IAX_SUBTYPE_AUTHREQ = 8
IAX_SUBTYPE_AUTHREP = 9
IAX_SUBTYPE_INVAL   = 10
IAX_SUBTYPE_LAGRQ   = 11
IAX_SUBTYPE_LAGRP   = 12
IAX_SUBTYPE_REGREQ  = 13
IAX_SUBTYPE_REGAUTH = 14
IAX_SUBTYPE_REGACK  = 15
IAX_SUBTYPE_REGREJ  = 16
IAX_SUBTYPE_REGREL  = 17
IAX_SUBTYPE_VNAK    = 18

=begin
      +------+-----------+-----------------------------------------+
      | Hex  | Name      | Description                             |
      +------+-----------+-----------------------------------------+
      | 0x01 | NEW       | Initiate a new call                     |
      |      |           |                                         |
      | 0x02 | PING      | Ping request                            |
      |      |           |                                         |
      | 0x03 | PONG      | Ping or poke reply                      |
      |      |           |                                         |
      | 0x04 | ACK       | Explicit acknowledgment                 |
      |      |           |                                         |
      | 0x05 | HANGUP    | Initiate call tear-down                 |
      |      |           |                                         |
      | 0x06 | REJECT    | Reject a call                           |
      |      |           |                                         |
      | 0x07 | ACCEPT    | Accept a call                           |
      |      |           |                                         |
      | 0x08 | AUTHREQ   | Authentication request                  |
      |      |           |                                         |
      | 0x09 | AUTHREP   | Authentication reply                    |
      |      |           |                                         |
      | 0x0a | INVAL     | Invalid message                         |
      |      |           |                                         |
      | 0x0b | LAGRQ     | Lag request                             |
      |      |           |                                         |
      | 0x0c | LAGRP     | Lag reply                               |
      |      |           |                                         |
      | 0x0d | REGREQ    | Registration request                    |
      |      |           |                                         |
      | 0x0e | REGAUTH   | Registration authentication             |
      |      |           |                                         |
      | 0x0f | REGACK    | Registration acknowledgement            |
      |      |           |                                         |
      | 0x10 | REGREJ    | Registration reject                     |
      |      |           |                                         |
      | 0x11 | REGREL    | Registration release                    |
      |      |           |                                         |
      | 0x12 | VNAK      | Video/Voice retransmit request          |
      |      |           |                                         |
      | 0x13 | DPREQ     | Dialplan request                        |
      |      |           |                                         |
      | 0x14 | DPREP     | Dialplan reply                          |
      |      |           |                                         |
      | 0x15 | DIAL      | Dial                                    |
      |      |           |                                         |
      | 0x16 | TXREQ     | Transfer request                        |
      |      |           |                                         |
      | 0x17 | TXCNT     | Transfer connect                        |
      |      |           |                                         |
      | 0x18 | TXACC     | Transfer accept                         |
      |      |           |                                         |
      | 0x19 | TXREADY   | Transfer ready                          |
      |      |           |                                         |
      | 0x1a | TXREL     | Transfer release                        |
      |      |           |                                         |
      | 0x1b | TXREJ     | Transfer reject                         |
      |      |           |                                         |
      | 0x1c | QUELCH    | Halt audio/video [media] transmission   |
      |      |           |                                         |
      | 0x1d | UNQUELCH  | Resume audio/video [media] transmission |
      |      |           |                                         |
      | 0x1e | POKE      | Poke request                            |
      |      |           |                                         |
      | 0x1f | Reserved  | Reserved for future use                 |
      |      |           |                                         |
      | 0x20 | MWI       | Message waiting indication              |
      |      |           |                                         |
      | 0x21 | UNSUPPORT | Unsupported message                     |
      |      |           |                                         |
      | 0x22 | TRANSFER  | Remote transfer request                 |
      |      |           |                                         |
      | 0x23 | Reserved  | Reserved for future use                 |
      |      |           |                                         |
      | 0x24 | Reserved  | Reserved for future use                 |
      |      |           |                                         |
      | 0x25 | Reserved  | Reserved for future use                 |
      +------+-----------+-----------------------------------------+
=end

IAX_IE_CALLED_NUMBER  = 1
IAX_IE_CALLING_NUMBER = 2
IAX_IE_AUTH_METHODS   = 3
IAX_IE_CALLING_NAME   = 4
IAX_IE_USERNAME       = 6
IAX_IE_DESIRED_CODEC  = 9
IAX_IE_ORIGINAL_DID   = 10
IAX_IE_ACTUAL_CODECS  = 8
IAX_IE_PROTO_VERSION  = 11
IAX_IE_REG_REFRESH    = 19
IAX_IE_CHALLENGE_DATA = 15
IAX_IE_CHALLENGE_RESP = 16
IAX_IE_APPARENT_ADDR  = 18
IAX_IE_REGREJ_CAUSE   = 22
IAX_IE_HANGUP_CAUSE   = 42

=begin
 +------+----------------+-------------------------------------------+
   | HEX  | NAME           | DESCRIPTION                               |
   +------+----------------+-------------------------------------------+
   | HEX  | NAME           | DESCRIPTION                               |
   | 0x01 | CALLED NUMBER  | Number/extension being called             |
   | 0x02 | CALLING NUMBER | Calling number                            |
   | 0x03 | CALLING ANI    | Calling number ANI for billing            |
   | 0x04 | CALLING NAME   | Name of caller                            |
   | 0x05 | CALLED CONTEXT | Context for number                        |
   | 0x06 | USERNAME       | Username (peer or user) for               |
   |      |                | authentication                            |
   | 0x07 | PASSWORD       | Password for authentication               |
   | 0x08 | CAPABILITY     | Actual CODEC capability                   |
   | 0x09 | FORMAT         | Desired CODEC format                      |
   | 0x0a | LANGUAGE       | Desired language                          |
   | 0x0b | VERSION        | Protocol version                          |
   | 0x0c | ADSICPE        | CPE ADSI capability                       |
   | 0x0d | DNID           | Originally dialed DNID                    |
   | 0x0e | AUTHMETHODS    | Authentication method(s)                  |
   | 0x0f | CHALLENGE      | Challenge data for MD5/RSA                |
   | 0x10 | MD5 RESULT     | MD5 challenge result                      |
   | 0x11 | RSA RESULT     | RSA challenge result                      |
   | 0x12 | APPARENT ADDR  | Apparent address of peer                  |
   | 0x13 | REFRESH        | When to refresh registration              |
   | 0x14 | DPSTATUS       | Dialplan status                           |
   | 0x15 | CALLNO         | Call number of peer                       |
   | 0x16 | CAUSE          | Cause                                     |
   | 0x17 | IAX UNKNOWN    | Unknown IAX command                       |
   | 0x18 | MSGCOUNT       | How many messages waiting                 |
   | 0x19 | AUTOANSWER     | Request auto-answering                    |
   | 0x1a | MUSICONHOLD    | Request musiconhold with QUELCH           |
   | 0x1b | TRANSFERID     | Transfer Request Identifier               |
   | 0x1c | RDNIS          | Referring DNIS                            |
   | 0x1d | Reserved       | Reserved for future use                   |
   | 0x1e | Reserved       | Reserved for future use                   |
   | 0x1f | DATETIME       | Date/Time                                 |
   | 0x20 | Reserved       | Reserved for future use                   |
   | 0x21 | Reserved       | Reserved for future use                   |
   | 0x22 | Reserved       | Reserved for future use                   |
   | 0x23 | Reserved       | Reserved for future use                   |
   | 0x24 | Reserved       | Reserved for future use                   |
   | 0x25 | Reserved       | Reserved for future use                   |
   | 0x26 | CALLINGPRES    | Calling presentation                      |
   | 0x27 | CALLINGTON     | Calling type of number                    |
   | 0x28 | CALLINGTNS     | Calling transit network select            |
   | 0x29 | SAMPLINGRATE   | Supported sampling rates                  |
   | 0x2a | CAUSECODE      | Hangup cause                              |
   | 0x2b | ENCRYPTION     | Encryption format                         |
   | 0x2c | ENCKEY         | Reserved for future Use                   |
   | 0x2d | CODEC PREFS    | CODEC Negotiation                         |
   | 0x2e | RR JITTER      | Received jitter, as in RFC 3550           |
   | 0x2f | RR LOSS        | Received loss, as in RFC 3550             |
   | 0x30 | RR PKTS        | Received frames                           |
   | 0x31 | RR DELAY       | Max playout delay for received frames in  |
   |      |                | ms                                        |
   | 0x32 | RR DROPPED     | Dropped frames (presumably by jitter      |
   |      |                | buffer)                                   |
   | 0x33 | RR OOO         | Frames received Out of Order              |
   | 0x34 | OSPTOKEN       | OSP Token Block                           |
   +------+----------------+-------------------------------------------+
=end


# Codecs
IAX_CODEC_G711_MULAW  = 0x00000004
IAX_CODEC_G711_ALAW   = 0x00000008
IAX_CODEC_LINEAR_PCM  = 0x00000040

# Supported
IAX_SUPPORTED_CODECS  = IAX_CODEC_G711_MULAW | IAX_CODEC_G711_ALAW | IAX_CODEC_LINEAR_PCM

# Default timings
IAX_DEFAULT_REG_REFRESH = 60
IAX_DEFAULT_TIMEOUT     = 10


end
end
end
