#!/usr/bin/env ruby
#

require 'rex/cloudcracker'

module Msf
  class Plugin::CloudCracker < Msf::Plugin
    class CloudCrackerCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      def name
        "CloudCracker"
      end

      def commands
        {
          'create_cloudcracker_job' => 'Create a new job',
          'create_stripe_payment' => 'Pay for a job via Stripe and receive your payment token',
          'create_bitcoin_payment' => 'Pay for a job via Bitcoin',
          'get_job_status' => 'Get the status of a previously created job',
          'get_dictionaries' => 'Get the available dictionaries and their prices',
        }
      end

      def cmd_create_stripe_payment(*args)

        if args.length == 0 || args[0] == "-h" || args[0] == "--help"
          print_status("Usage: create_stripe_payment -c <credit_card> -s <security_code> -e <expiration> -j job_reference")
          print_status("\t-c\tThe credit card to charge")
          print_status("\t-s\tThe 3 or 4 digit security code")
          print_status("\t-e\tThe card expiration date")
          print_status("\t-j\tThe job ID returned by create_cloudcracker_job")
          print_status("\t-f\tThe job format (wpa ntlm cryptsha512 cryptmd5)")
          return
        end

        opts = Rex::Parser::Arguments.new(
          '-c' => [true, "The credit card number to charge"],
          '-s' => [true, "The security code to use"],
          '-e' => [true, "The cards expiration date in MM/YYYY format"],
          '-j' => [true, "The job ID of the job created with create_cloudcracker_job"],
          '-f' => [true, "The format of the job (wpa ntlm cryptsha512 cryptmd5)"]
        )

        format = ""
        credit_card = ""
        expiration = ""
        security_code = ""
        job_reference = nil
        opts.parse(args) do |opt, idx, val|
          case opt
          when "-c"
            credit_card = val
          when "-s"
            security_code = val
          when "-f"
            format = val
          when "-e"
            expiration = val
          when '-j'
            job_reference = val
          end
        end

        if not job_reference
          print_error("Please pass a CloudCracker job ID so I can verify your purchase.")
          return
        end

        #this isn't awesome, but it is simple. Could be a bit more defensive.
        if expiration !~ /\d{2}\/\d{4}/ 
          print_error("Expiry date not valid: #{expiration}")
          return
        end

        exp_month = expiration.split('/')[0]
        exp_year = expiration.split('/')[1]

        client = Rex::Proto::Http::Client.new('api.stripe.com', 443, {}, true, 'SSLv3')
        query =  "card[number]=#{credit_card}"
        query << "&card[cvc]=#{security_code}"
        query << "&card[exp_month]=#{exp_month}"
        query << "&card[exp_year]=#{exp_year}"

        req = client.request_cgi(
          'uri' => "/v1/tokens",
          'query' => query,
          'method' => "POST",
          'headers' => {

          },
          'basic_auth' =>  'pk_XW3m8FFAXOCI8sz3aHKWsfGowofO4:'
        )

        res = client.send_recv(req, 300)

        if res.nil? || res.body.nil?
          print_error("Request failed.")
          return 
        end

        res = JSON.parse(res.body)
        res = verify_stripe_payment(res["id"], job_reference, format)

        if res["error"]
          print_error(res["error"])
        else
          print_good("Payment accepted, your job will begin shortly and will take an hour or two.")
        end
      end

      def cmd_create_bitcoin_payment(*args)
        print_error("Bitcoin payments aren't supported yet. Please send pull request.")
        return
      end

      def cmd_create_cloudcracker_job(*args)
        if args.length == 0 || args[0] == "-h" || args[0] == "--help"
          print_status("Usage: create_cloudcracker_job -t type -m hash_format -f hash_file -e email@address.com -d dictionary -s dict_size")
          print_status("\t-t\tThe type of job to create. Either hash or wpa")
          print_status("\t-f\tThe text file containing the hash(es)")
          print_status("\t-e\tThe email address to send results to")
          print_status("\t-m\tThe format of the hashes (ntlm cryptsha512 cryptmd5)")
          print_status("\t-d\tThe dictionary to use, provided by get_dictionaries <type>")
          print_status("\t-s\tThe size of dictionary to use, provided by get_dictionaries <type>")
          print_status("\t-n\tThe network name (essid) of the pcap handshake")
          return
        end

        opts = Rex::Parser::Arguments.new(
          "-t" => [true, "The type of job to create. Either hash or wpa"],
          "-f" => [true, "The hash file or pcap file"],
          "-e" => [true, "The email address to send results to"],
          "-d" => [true, "The dictionary to use, provided by get_dictionaries <type>"],
          "-m" => [true, "The format of the hashes"],
          "-s" => [true, "The size of the dictionary to use, provided by get_dictionaries <type>"],
          "-n" => [false, "The network name (essid) of the pcap handshake"]
        )

        type = ""
        file = ""
        email = ""
        dictionary = ""
        size = ""
        essid = ""
        format = ""

        opts.parse(args) do |opt, idx, val|
          case opt
          when "-t"
            type = val
          when "-m"
            format = val
          when "-f"
            file = val
          when "-e"
            email = val
          when "-d"
            dictionary = val
          when "-s"
            size = val
          when "-n"
            essid = val
          end
        end

        if type == "hash"
          job = Rex::CloudCracker::HashJob.new
          job.hashes_file = file
          job.format = format 
          job.email = email
          job.dictionary = dictionary
          job.dictionary_size = size
          job.is_test = true
          job.msfframework = framework
          job.parent_mechanism = "Metasploit-CloudCracker-Plugin"
          job.parent_mechanism_version = "1.0"
          res = job.submit_hash_job
        elsif type == "wpa"
          job = Rex::CloudCracker::WPAJob.new
          job.pcap_file = file
          job.essid = essid
          job.email = email
          job.dictionary = dictionary
          job.dictionary_size = size
          job.msfframework = framework
          job.is_test = true
          res = job.submit_wpa_job
        else
          print_error("Unknown job type")
          return
        end

        if res['error']
          print_error "Error: " + res['error']
        else
          print_good("Job reference ID: " + res["reference"])
        end
      end

      def verify_stripe_payment(stripe_token, job_reference, format)
        client = Rex::Proto::Http::Client.new('www.cloudcracker.com', 443, {}, true, "SSLv3")

        uri = ""
        uri << "/test"
        uri << "/api/#{format}/payment/#{job_reference}"

        doc = Rex::MIME::Message.new
        doc.add_part(stripe_token, nil, nil, "form-data; name=stripeToken")

        req = client.request_raw(
          'uri' => uri,
          'method' => 'POST',
          'headers' => {
          'Content-Type' => 'multipart/form-data; boundary=' + doc.bound,
          'Content-Length' => doc.to_s.length
        },
          'data' => doc.to_s
        )

        res = client.send_recv(req, 300)

        raise "Request failed." if res.nil? || res.body.nil?

        return JSON.parse(res.body)
      end

      def cmd_get_job_status(*args)
        if args.length == 0 || args[0] == "-h" || args[0] == "--help"
          print_status("Usage: get_job_status <format> <job_id>")
          return
        end

        format = args[0]
        job_reference = args[1]
        res = Rex::CloudCracker::Job.new().get_status job_reference, format

        print_status("\tStatus:\t\t#{res["status"]}")
        print_status("\tTime Elapsed:\t#{res["elapsedTime"]}")
        print_status("\tResults:\t#{res["results"] || "No results"}")
        print_status("\tProgress:\t#{res["progress"]}")
      end

      def cmd_get_dictionaries(*args)
        if args[0] == "-h" || args[0] == "--help"
          print_status("Usage: get_dictionaries <format>")
          print_status("\tSupported formats: wpa ntlm cryptsha512 cryptmd5")
          return
        end

        format = args[0]

        dictionaries = Rex::CloudCracker::Dictionaries.get_dictionaries format
        dictionaries.each do |dictionary|
          print_status("Dictionary ID: " + dictionary['name'])
          print_status(dictionary['description'])
          table = Rex::Ui::Text::Table.new(
            'Header' => "Size options for format: " + format,
            'Indent' =>  '    '.length,
            'Columns' => %w[Count Time Price MinimumPrice]
          )

          dictionary['sizes'].each do |size|
            table << [size['count'].to_s + " million", size['time'].to_s + " minutes", (size['price'].to_i / 100).to_s + " USD", (size['minimum_price'].to_i / 100).to_s + " USD"]
          end

          print(table.to_s)
          print_status("")
          print_status("")
        end
      end
    end

    def initialize(framework, opts)
      super
      add_console_dispatcher(CloudCrackerCommandDispatcher)
      banner = ["0a205f5f5f5f5f205f20202020202020202020202020202020205f205f5f5f5f5f202020202020202020202020202020205f202020202020202020202020200a2f20205f5f205c207c2020202020202020202020202020207c202f20205f5f205c20202020202020202020202020207c207c2020202020202020202020200a7c202f20205c2f207c205f5f5f20205f2020205f20205f5f7c207c202f20205c2f5f205f5f205f5f205f20205f5f5f7c207c205f5f5f5f5f205f205f5f200a7c207c2020207c207c2f205f205c7c207c207c207c2f205f60207c207c2020207c20275f5f2f205f60207c2f205f5f7c207c2f202f205f205c20275f5f7c0a7c205c5f5f2f5c207c20285f29207c207c5f7c207c20285f7c207c205c5f5f2f5c207c207c20285f7c207c20285f5f7c2020203c20205f5f2f207c2020200a205c5f5f5f5f2f5f7c5c5f5f5f2f205c5f5f2c5f7c5c5f5f2c5f7c5c5f5f5f5f2f5f7c20205c5f5f2c5f7c5c5f5f5f7c5f7c5c5f5c5f5f5f7c5f7c2020200a20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020205f2020202020200a20202020202020202020202020202020202020202020202020202020205f5f5f5f202020202020202020202020202020202020202020285f2920202020200a202020202020202020202020202020202020202020202020202020202f205f5f205c205f205f5f205f5f5f2020205f5f5f5f5f20205f5f5f20205f5f5f200a2020202020202020202020202020202020202020202020202020202f202f205f60207c20275f2060205f205c202f205f205c205c2f202f207c2f205f205c0a20202020202020202020202020202020202020202020202020207c207c20285f7c207c207c207c207c207c207c20285f29203e20203c7c207c20205f5f2f0a2020202020202020202020202020202020202020202020202020205c205c5f5f2c5f7c5f7c207c5f7c207c5f7c5c5f5f5f2f5f2f5c5f5c5f7c5c5f5f5f7c0a202020202020202020202020202020202020202020202020202020205c5f5f5f5f2f202020202020202020202020202020202020202020202020202020200a20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a0a"].pack("H*")
      print(banner)
      print_status("CloudCracker integration has been activated")
    end

    def cleanup
      remove_console_dispatcher('CloudCracker')
    end

    def name
      "cloudcracker"
    end

    def desc
      "Integrates CloudCracker with Metasploit Console"
    end
  end
end
