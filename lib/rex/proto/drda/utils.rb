# -*- coding: binary -*-
require 'rex/proto/drda'

module Rex
module Proto
module DRDA
class Utils

  # Creates a packet with EXCSAT_DDM and an ACCSEC_DDM. This will elicit
  # a reponse from the target server.
  def self.client_probe(dbname=nil)
    pkt = [
      EXCSAT_DDM.new,
      ACCSEC_DDM.new(:dbname => dbname)
    ]
    pkt.map {|x| x.to_s}.join
  end

  # Creates a packet with EXCSAT_DDM and an SECCHK_DDM.
  # In order to ever succeed, you do need a successful probe first.
  def self.client_auth(args={})
    dbname = args[:dbname]
    dbuser = args[:dbuser]
    dbpass = args[:dbpass]
    pkt = [
      ACCSEC_DDM.new(:format => 0x41),
      SECCHK_DDM.new(:dbname => dbname, :dbuser => dbuser, :dbpass => dbpass)
    ]
    pkt.map {|x| x.to_s}.join
  end

  def self.server_packet_info(obj)
    info_hash = {}
    return info_hash unless obj.kind_of? Rex::Proto::DRDA::SERVER_PACKET
    obj.each do |ddm|
      case ddm.codepoint
      when Constants::EXCSATRD
        info_hash.merge!(_info_excsatrd(ddm))
      when Constants::ACCSECRD
        info_hash.merge!(_info_accsecrd(ddm))
      when Constants::RDBNFNRM
        info_hash.merge!(_info_rdbnfnrm(ddm))
      when Constants::SECCHKRM
        info_hash.merge!(_info_secchkrm(ddm))
      else
        next
      end
    end
    return info_hash
  end

  def self._info_excsatrd(ddm)
    info_hash = {:excsatrd => true}
    ddm.payload.each do |param|
      case param.codepoint
      when Constants::SRVNAM
        info_hash[:instance_name] = Rex::Text.from_ebcdic(param.payload)
      when Constants::SRVCLSNM
        info_hash[:platform] = Rex::Text.from_ebcdic(param.payload)
      when Constants::SRVRLSLV
        info_hash[:version] = Rex::Text.from_ebcdic(param.payload)
      else
        next
      end
    end
    return info_hash
  end

  def self._info_accsecrd(ddm)
    info_hash = {:accsecrd => true}
    ddm.payload.each do |param|
      case param.codepoint
      when Constants::SECMEC
        info_hash[:plaintext_auth] = true if param.payload =~ /\x00\x03/
      when Constants::SECCHKCD
        info_hash[:security_check_code] = param.payload.unpack("C").first
        # A little spurious? This is always nonzero when there's no SECCHKRM DDM.
        info_hash[:db_login_success] = false unless info_hash[:security_check_code].zero?
      else
        next
      end
    end
    return info_hash
  end

  def self._info_rdbnfnrm(ddm)
    info_hash = {:rdbnfnrm => true}
    info_hash[:database_found] = false
    ddm.payload.each do |param|
      case param.codepoint
      when Constants::RDBNAM
        info_hash[:db_name] = Rex::Text.from_ebcdic(param.payload).unpack("A*").first
      when Constants::SRVDGN
        info_hash[:error_message] = Rex::Text.from_ebcdic(param.payload)
      else
        next
      end
    end
    return info_hash
  end

  def self._info_secchkrm(ddm)
    info_hash = {:secchkrm => true}
    ddm.payload.each do |param|
      case param.codepoint
      when Constants::SRVCOD
        info_hash[:severity_code] = param.payload.unpack("n").first
      when Constants::SECCHKCD
        info_hash[:security_check_code] = param.payload.unpack("C").first
      else
        next
      end
    end
    if info_hash[:serverity].to_i.zero? and info_hash[:security_check_code].to_i.zero?
      info_hash[:db_login_success] = true
    end
    return info_hash
  end

end

end
end
end
