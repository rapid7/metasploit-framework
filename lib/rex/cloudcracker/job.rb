require 'rex/proto/http'
require 'json'

module Rex
module CloudCracker
  #HashJob and WPAJob both inherit from this class
  class Job

    #is_test allows you to play with the API in a sandbox of a sort
    attr_accessor :is_test, :msfframework

    def self.create_stripe_payment(credit_card, security_code, exp_month, exp_year, job_reference, format)
      client = Rex::Proto::Http::Client.new('api.stripe.com', 443, {}, true, 'SSLv3')

      query =  "card[number]=#{credit_card}"
      query << "&card[cvc]=#{security_code}"
      query << "&card[exp_month]=#{exp_month}"
      query << "&card[exp_year]=#{exp_year}"

      req = client.request_cgi(
        'uri' => '/v1/tokens',
        'query' => query,
        'method' => 'POST',
        'basic_auth' => 'pk_XW3m8FFAXOCI8sz3aHKWsfGowofO4:'
      )

      res = client.send_recv(req, 300)

      if res.nil? || res.body.nil?
        raise "Request failed"
      end

      res = JSON.parse(res.body)
      res = self.verify_stripe_payment(res["id"], job_reference, format)

      if res["error"]
        raise res["error"]
      else
        return res
      end
    end

    def self.verify_stripe_payment(stripe_token, job_reference, format)
      client = Rex::Proto::Http::Client.new('www.cloudcracker.com', 443, {}, true, 'SSLv3')

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

    def self.get_bitcoin_payment_info job_reference, format
      client = Rex::Proto::Http::Client.new('www.cloudcracker.com', 443, {}, true, "SSLv3")

      uri = ""
      uri << "/test"
      uri << "/api/" + format + "/payment/" + job_reference

      req = client.request_cgi(
        'uri' => uri,
        'method' => 'GET'
      )

      printf req
      res = client.send_recv(req)

      raise "Response failed" if res.nil? or res.body.nil?

      return JSON.parse(res.body)
    end

    def self.get_status job_reference, format

      client = Rex::Proto::Http::Client.new('www.cloudcracker.com', 443, {}, true, "SSLv3")

      uri = ""
      uri << "/test"
      uri << "/api/" + format + "/job/" + job_reference

      req = client.request_cgi(
        'uri' => uri,
        'method' => 'GET'
      )

      res = client.send_recv(req, 300)

      raise "Response or response body nil" if res.nil? || res.body.nil?

      return JSON.parse(res.body)
    end

    #At the time of writing, NTLM jobs accept up to 400 hashes
    #NTLM must be in PWDUMP format
    #crypt* only allow one hash per job
    def submit_job(job_type, opts)
      formats = %w[wpa ntlm cryptsha512 cryptmd5]

      raise "Invalid format" if not formats.include? opts[:format]

      client = Rex::Proto::Http::Client.new("www.cloudcracker.com", 443, {}, true, "SSLv3")
      format = (job_type =~ /wpa/ ? 'wpa' : opts[:format])

      uri = ""
      uri = uri + "/test" if @is_test
      uri = uri + "/api/" + format + "/job"

      #read in the hashes or pcap file
      file = File.new(opts[:file]).read

      #CloudCracker expects a multipart/form-data POST request with all the data needed to start the job
      post_data = Rex::MIME::Message.new

      if job_type =~ /hash/
        post_data.add_part(file,"application/octet-stream",nil,'form-data; name=hashes; filename=fdsa.txt')
      elsif job_type =~ /wpa/
        post_data.add_part(file, "application/octet-stream", nil, 'form-data; name=pcap filename=fdsa.pcap')
        post_data.add_part(opts[:essid], nil, nil, 'form-data; name=essid')
      end

      post_data.add_part(opts[:dictionary], nil, nil, 'form-data; name=dictionary')
      post_data.add_part(opts[:dictionary_size], nil, nil, 'form-data; name=size')
      post_data.add_part(opts[:email], nil, nil, 'form-data; name=email')

      mech = opts[:mechanism] || "General"
      mech_version = opts[:mechanism_version] || "0.0"

      #if librex gets gemified again, @msfframework will be nil
      framework_version = (@msfframework ? @msfframework.version : "N/A")

      req = client.request_raw(
        'uri' => uri,
        'method' => 'POST',
        'headers' => {
          #The key in the first key-value pair of this should not change (only the dynamic version)
          #The second key-value pair is allowed to describe the mechanism consuming the service, and the version of this mechanism
          'User-Agent' => 'Metasploit-Framework-Version/' + framework_version + '; ' + mech + '/' + mech_version,
          'Accept-Encoding' => 'gzip, deflate',
          'Referer' => 'https://www.cloudcracker.com/',
          'Content-Length' => post_data.to_s.length,
          'Content-Type' => 'multipart/form-data; boundary=' + post_data.bound
      },
        'data' => post_data.to_s
      )

      res = client.send_recv(req, 300)

      raise "Response/response body nil" if res.nil? or res.body.nil?

      #CloudCracker API returns JSON
      #Let's parse this into a nice hash :)
      begin
        return JSON.parse(res.body)
      rescue
        return nil
      end
    end
  end
end
end
