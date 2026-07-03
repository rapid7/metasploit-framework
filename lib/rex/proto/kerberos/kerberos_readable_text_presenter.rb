# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      # Presenter for formatting Kerberos data structures as human-readable text
      class KerberosReadableTextPresenter
        READABLE_TEXT_LABELS = {
          'pvno' => 'Protocol Version',
          'msg_type' => 'Message Type',
          'pa_data' => 'Pre-Authentication Data',
          'req_body' => 'Request Body',
          'crealm' => 'Client Realm',
          'cname' => 'Client Name',
          'realm' => 'Realm',
          'sname' => 'Server Name',
          'enc_part' => 'Encrypted Part',
          'etype' => 'Encryption Type',
          'name_type' => 'Name Type',
          'name_string' => 'Name String',
          'error_code' => 'Error Code',
          'e_data' => 'Error Data',
          'etext' => 'Error Text',
          'stime' => 'Server Time',
          'ctime' => 'Client Time',
          'susec' => 'Server Microseconds',
          'cusec' => 'Client Microseconds',
          'ap_options' => 'AP Options',
          'kdc_options' => 'KDC Options',
          'ticket' => 'Ticket',
          'tkt_vno' => 'Ticket Version Number',
          'kvno' => 'Key Version Number',
          'flags' => 'Flags'
        }.freeze

        def present(serialized_message)
          lines = []
          case serialized_message
          when Hash
            append_hash(lines, serialized_message, indent: 0)
          when Array
            append_array(lines, serialized_message, indent: 0)
          else
            lines << serialized_message.to_s
          end
          lines.join("\n")
        end

        private

        def append_hash(lines, value, indent:)
          value.each do |key, entry|
            append_field(lines, key, entry, indent: indent)
          end
        end

        def append_field(lines, key, value, indent:)
          label = readable_text_label(key)
          spacing = ' ' * indent
          case value
          when Hash
            lines << "#{spacing}#{label}:"
            append_hash(lines, value, indent: indent + 2)
          when Array
            if value.empty?
              lines << "#{spacing}#{label}: []"
            else
              lines << "#{spacing}#{label}:"
              append_array(lines, value, indent: indent + 2)
            end
          else
            lines << "#{spacing}#{label}: #{value}"
          end
        end

        def append_array(lines, value, indent:)
          spacing = ' ' * indent
          value.each_with_index do |entry, index|
            case entry
            when Hash
              lines << "#{spacing}Entry[#{index}]:"
              append_hash(lines, entry, indent: indent + 2)
            when Array
              lines << "#{spacing}Entry[#{index}]:"
              append_array(lines, entry, indent: indent + 2)
            else
              lines << "#{spacing}- #{entry}"
            end
          end
        end

        def readable_text_label(key)
          READABLE_TEXT_LABELS[key.to_s] || key.to_s.split('_').map(&:capitalize).join(' ')
        end
      end
    end
  end
end
