##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rexml/document'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'CorpWatch Company ID Information Search',
      'Description'    => %q{
        This module interfaces with the CorpWatch API to get publicly available
        info for a given CorpWatch ID of the company.  If you don't know the
        CorpWatch ID, please use the corpwatch_lookup_name module first.
      },
      'Author'         => [ 'Brandon Perry <bperry.volatile[at]gmail.com>' ],
      'References'     =>
        [
          [ 'URL', 'http://api.corpwatch.org/' ]
        ]
    ))

    register_options(
      [
        OptString.new('CW_ID', [ true, "The CorpWatch ID of the company", ""]),
        OptInt.new('YEAR', [ false, "Year to look up"]),
        OptBool.new('GET_LOCATIONS', [ false, "Get locations for company", true]),
        OptBool.new('GET_NAMES', [ false, "Get all registered names ofr the company", true]),
        OptBool.new('GET_FILINGS', [ false, "Get all filings", false ]),
        OptBool.new('GET_CHILDREN', [false, "Get children companies", true]),
        OptInt.new('CHILD_LIMIT', [false, "Set limit to how many children we can get", 5]),
        OptBool.new('GET_HISTORY', [false, "Get company history", false])
      ], self.class)

    deregister_options('RHOST', 'RPORT', 'VHOST', 'Proxies')
  end

  def cleanup
    datastore['RHOST'] = @old_rhost
    datastore['RPORT'] = @old_rport
  end

  def run
    # Save the original rhost/rport in case the user was exploiting something else
    @old_rhost = datastore['RHOST']
    @old_rport = datastore['RPORT']

    # Initial api.corpwatch.org's rhost and rport for HttpClient
    datastore['RHOST'] = 'api.corpwatch.org'
    datastore['RPORT'] = 80

    loot = ""
    uri = "/"
    uri << (datastore['YEAR']).to_s if datastore['YEAR'].to_s != ""
    uri << ("/companies/" + datastore['CW_ID'])

    res = send_request_cgi({
      'uri'      => uri + ".xml",
      'method'   => 'GET'
    }, 25)

    if res == nil
      print_error("No response from server.")
      return
    end

    begin
      doc = REXML::Document.new(res.body)
    rescue
      print_error("Malformed XML or broken response")
      return
    end

    root = doc.root

    if doc.root == nil
      print_error("No document root, no results returned")
      return
    end

    elements = root.get_elements("result")

    if elements == nil || elements.length == 0
      print_error("No results returned")
      return
    end

    results = elements[0]

    if results == nil
      print_error("No results returned")
      return
    end

    elements = results.get_elements("companies")

    if elements == nil || elements.length == 0
      print_error("No companies returned")
      return
    end

    results = elements[0]

    if results == nil || results.elements == nil
      print_error("No results returned")
      return
    end

    results.elements.each { |e|
      loot << ("CorpWatchID: " + (cwid = grab_text(e, "cw_id")))
      loot << ("\nCentral Index Key " + (cik = grab_text(e, "cik")))
      loot << ("\nName: " + (name = grab_text(e, "company_name")))
      loot << ("\nIRS Number: " + (irsno = grab_text(e, "irs_number")))
      loot << ("\nSIC Code: " + (sic_code = grab_text(e, "sic_code")))
      loot << ("\nSector: " + (sector = grab_text(e, "sector_name")))
      loot << ("\nSource: " + (source = grab_text(e, "source_type")))
      loot << ("\nAddress: " + (address = grab_text(e, "raw_address")))
      loot << ("\nCountry: " + ( country = grab_text(e, "country_code")))
      loot << ("\nSub-Division: " + (subdiv = grab_text(e, "subdiv_code")))
      loot << ("\nTop Parent CW_ID: " + (top_parent = grab_text(e, "top_parent_id")))
      loot << ("\nNumber of parents: " + (num_parents = grab_text(e, "num_parents")))
      loot << ("\nNumber of children: " + (num_children = grab_text(e, "num_children")))
      loot << ("\nMax searchable year: " + (max_year = grab_text(e, "max_year")))
      loot << ("\nMinimum searchable year: "+ (min_year = grab_text(e, "min_year")))
      loot << "\n\n\n"

      print_status("Basic Information\n--------------------")
      print_status("CorpWatch ID: " + cwid)
      print_status("Central Index Key (CIK): " + cik)
      print_status("Full Name: " + name)
      print_status("IRS Number: " + irsno)
      print_status("SIC Code: " + sic_code)
      print_status("Sector: " + sector)
      print_status("Source Type: " + source)

      print_line("")
      print_status("Address and Location Information\n-----------------------------")
      print_status("Full Address: " + address)
      print_status("Country Code: " + country)
      print_status("Subdivision: " + subdiv)

      print_line("")
      print_status("Parent and Children Information\n---------------------------")
      print_status("Top Parent ID: " + top_parent)
      print_status("Number of parent companies: " + num_parents)
      print_status("Number of child companies: " + num_children)
      print_status("Max lookup year: " + max_year)
      print_status("Min lookup year: " + min_year)
    }

    if datastore['GET_LOCATIONS']

      res = send_request_cgi(
      {
        'uri'     => uri + "/locations.xml",
        'method'  => 'GET'
      }, 25)

      if res == nil
        print_error ("Server down or bad response")
        return
      end

      begin
        doc = REXML::Document.new(res.body)
      rescue
        print_error("Query returned bad or poorly formatted data.")
        return
      end

      root = doc.root

      elements = root.get_elements("result")

      if elements == nil || elements.length == 0
        print_error("no results returned")
        return
      end

      results = elements[0]

      if results == nil
        print_status("No results returned")
      else
        results = results.get_elements("locations")[0]

        results.elements.each { |e|
          loot << ("CorpWatch ID: " + (cwid = grab_text(e, "cw_id")))
          loot << ("\nCountry code: " + (country_code = grab_text(e, "country_code"))
          loot << ("\nSubdivision code: " + (subdiv_code = grab_text(e, "subdiv_code")))
          loot << ("\nType: " + (type = grab_text(e, "type")))
          loot << ("\nFull address: " + full_address = grab_text(e, "raw_address")))
          loot << ("\nStreet 1: " + (street1 = grab_text(e, "street_1")))
          loot << ("\nStreet 2: " + (street2 = grab_text(e, "street_2")))
          loot << ("\nCity: " + (city = grab_text(e, "city")))
          loot << ("\nState: " + (state = grab_text(e, "state")))
          loot << ("\nZIP: " + (zip = grab_text(e, "postal_code")))
          loot << ("\nDate valid: " + (date_valid = grab_text(e, "date")))
          loot << ("\nMax searchable year: " + (max_year = grab_text(e, "max_year")))
          loot << ("\nMin searchable year: " + (min_year = grab_text(e, "min_year")))
          loot << "\n\n\n"

          print_line("")
          print_status("Detailed Location Information\n----------------------------------")
          print_status("Country Code: " + country_code)
          print_status("Subdivision: " + subdiv_code)
          print_status("Residential/Business address: " + type)
          print_status("Full Address: " + full_address)
          print_status("Street 1: " + street1)
          print_status("Street 2: " + street2)
          print_status("City: " + city)
          print_status("State:" + state)
          print_status("Postal Code: " + zip)
          print_status("Date address was valid: " + date_valid)
          print_status("Max lookup year: " + max_year)
          print_status("Min lookup year: " + min_year)
        }
      end
    end

    if datastore['GET_NAMES']

      res = send_request_cgi(
      {
        'uri'     => uri + "/names.xml",
        'method'  => 'GET'
      }, 25)

      if res == nil
        print_error("Server down or bad response")
        return
      end

      begin
        doc = REXML::Document.new(res.body)
      rescue
        print_error("Query returned bad or poorly formatted XML")
        return
      end

      root = doc.root

      if root == nil
        print_error("document root nil")
        return
      end

      elements = root.get_elements("result")

      if elements == nil || elements.length == 0
        print_error("Returned no or broken results")
        return
      end

      results = elements[0]

      if results == nil
        print_status("No results returned")
      else
        results = results.get_elements("names")[0]

        results.elements.each { |e|
          loot << ("Name: " + (name = grab_text(e, "company_name")))
          loot << ("\nSource: " + (source = grab_text(e, "source")))
          loot << ("\nDate: " + (date = grab_text(e, "date")))
          loot << ("\nMax searchable year: " + (max_year = grab_text(e, "max_year")))
          loot << ("\nMin searchable year: " + (min_year = grab_text(e, "min_year")))
          loot << "\n\n\n"

          print_line("\n")
          print_status("Detailed Name Information\n---------------------------")
          print_status("Name: " + name)
          print_status("Source: " + source)
          print_status("Date valid: " + date)
          print_status("Max lookup year: " + max_year)
          print_status("Min lookup year: " + min_year)
        }
      end
    end

    if datastore['GET_FILINGS']

      res = send_request_cgi(
      {
        'uri'     => uri + "/filings.xml",
        'method'  => 'GET'
      }, 25)

      if res == nil
        print_error("Server down or response broken")
        return
      end

      begin
        doc = REXML::Document.new(res.body)
      rescue
        print_error("Query return bad or broken data")
        return
      end

      root = doc.root

      elements = root.get_elements("result")

      if elements == nil || elements.length == 0
        print_error("Results were either broken or not returned")
        return
      end

      results = elements[0]

      if results == nil
        print_status("No results returned")
      else
        elements = results.get_elements("filings")

        if elements == nil
          print_error("Results broken or not returned")
          return
        end

        results = elements[0]

        if results == nil
          print_status("No filings found")
        else
          results.elements.each { |e|
            loot << ("Central Index Key: " + (cik = grab_text(e, "cik")))
            loot << ("\nYear filed: " + (year_filed = grab_text(e, "year")))
            loot << ("\nQuarter filed: " + (quarter_filed = grab_text(e, "quarter")))
            loot << ("\nReport period: " + (report_period = grab_text(e, "period_of_report")))
            loot << ("\nFiling date: " + (filing_date = grab_text(e, "filing_date")))
            loot << ("\nForm 10k: " + (form10k = grab_text(e, "form_10K_url")))
            loot << ("\nSEC21: " + (sec21 = grab_text(e, "sec_21_url")))
            loot << ("\nIs a filer: " + (is_filer = grab_text(e, "company_is_filer")))
            loot << "\n\n\n"

            print_line("\n")
            print_status("Detailed Filing Information\n---------------------")
            print_status("Central Index Key: " + cik)
            print_status("Year filed: " + year_filed)
            print_status("Quarter Filed: " + quarter_filed)
            print_status("Report Period: " + report_period)
            print_status("Filing Date: " + filing_date)
            print_status("10K Filing Form: " + form10k)
            print_status("SEC 21 Form: " + sec21)
            print_status("Company is active filer: " + (is_filer == "1" ? "true" : "false"))
          }
        end
      end
    end

    if datastore['GET_CHILDREN']
      child_uri = (uri + "/children.xml")

      if datastore['CHILD_LIMIT'] != nil
        child_uri << "?limit=#{datastore['CHILD_LIMIT']}"
        print_status("Limiting children results to 5")
      end

      res = send_request_cgi(
      {
        'uri'      => child_uri,
        'method'   => 'GET'
      }, 25)

      if res == nil
        print_error("Server down or bad response")
        return
      end

      begin
        doc = REXML::Document.new(res.body)
      rescue
        print_error("Query return bad or broken data")
        return
      end

      root = doc.root

      elements = root.get_elements("result")

      results = elements[0]

      if results == nil
        print_status("No results were returned.")
      else
        results = results.get_elements("companies")[0]

        if results == nil
          print_status("No results returned")
        else
          results.elements.each { |e|
            loot << ("CorpWatch ID: " + (cwid = grab_text(e, "cw_id")))
            loot << ("\nCentral Index Key: " + (cik = grab_text(e, "cik")))
            loot << ("\nCompany Name: " + (name = grab_text(e, "company_name")))
            loot << ("\nIRS number: " + (irsno = grab_text(e, "irs_number")))
            loot << ("\nSIC Code: " + (sic_code = grab_text(e, "sic_code")))
            loot << ("\nSector: " + (sector = grab_text(e, "sector_name")))
            loot << ("\nSource: " + (source = grab_text(e, "source_type")))
            loot << ("\nAddress: " + (address = grab_text(e, "raw_address")))
            loot << ("\nCountry: " + (country = grab_text(e, "country_code")))
            loot << ("\nSubdivision: " + (subdiv = grab_text(e, "subdiv_code")))
            loot << ("\nTop parent: " + (top_parent = grab_text(e, "top_parent_id")))
            loot << ("\nNumber of parents: " + (num_parents = grab_text(e, "num_parents")))
            loot << ("\nNumber of children: " + (num_children = grab_text(e, "num_children")))
            loot << ("\nMax searchable year: " + (max_year = grab_text(e, "max_year")))
            loot << ("\nMin searchable year: " + (min_year = grab_text(e, "min_year")))
            loot << "\n\n\n"

            print_line("\n")
            print_status("Child Information\n--------------------")
            print_status("CorpWatch ID: " + cwid)
            print_status("Central Index Key (CIK): " + cik)
            print_status("Full Name: " + name)
            print_status("IRS Number: " + irsno)
            print_status("SIC Code: " + sic_code)
            print_status("Sector: " + sector)
            print_status("Source Type: " + source)

            print_line("")
            print_status("Address and Location Information\n-----------------------------")
            print_status("Full Address: " + address)
            print_status("Country Code: " + country)
            print_status("Subdivision: " + subdiv)

            print_line("")
            print_status("Parent and Children Information\n---------------------------")
            print_status("Top Parent ID: " + top_parent)
            print_status("Number of parent companies: " + num_parents)
            print_status("Number of child companies: " + num_children)
            print_status("Max lookup year: " + max_year)
            print_status("Min lookup year: " + min_year)
          }
        end
      end
    end

    if datastore['GET_HISTORY']

      res = send_request_cgi({
        'uri'     => uri + "/history.xml",
        'method'  => 'GET'
      }, 25)

      if res == nil
        print_error("Server down or bad response")
        return
      end

      begin
        doc = REXML::Document.new(res.body)
      rescue
        print_error("Query return bad or broken data")
        return
      end

      root = doc.root

      elements = root.get_elements("result")

      if elements == nil || elements.length == 0
        print_error("No results.")
        return
      end

      results = elements[0]

      if results == nil
        print_status("No results returned.")
      else
        results = results.get_elements("companies")[0]

        results.elements.each { |e|
          loot << ("CorpWatch ID: " + (cwid = grab_text(e, "cw_id")))
          loot << ("\nCentral Index Key: " + (cik = grab_text(e, "cik")))
          loot << ("\nIRS Number: " + (irsno = grab_text(e, "irs_number")))
          loot << ("\nSIC Code: " + (sic_code = grab_text(e, "sic_code")))
          loot << ("\nIndustry: " + (industry = grab_text(e, "industry_name")))
          loot << ("\nSector: " + (sector = grab_text(e, "sector_name")))
          loot << ("\nSIC Sector: " + (sic_sector = grab_text(e, "sic_sector")))
          loot << ("\nSource: " + (source = grab_text(e, "source_type")))
          loot << ("\nAddress: " + (address = grab_text(e, "raw_address")))
          loot << ("\nCountry: " + (country_code = grab_text(e, "country_code")))
          loot << ("\nSub-division Code: " + (subdiv_code = grab_text(e, "subdiv_code")))
          loot << ("\nTop parent ID: " + (top_parent = grab_text(e, "top_parent_id")))
          loot << ("\nNumber of parents: " + (num_parents = grab_text(e, "num_parents")))
          loot << ("\nNumber of children: " + (num_children = grab_text(e, "num_children")))
          loot << ("\nMax searchable year: " + (max_year = grab_text(e, "max_year")))
          loot << ("\nMin searchable year: " + (min_year = grab_text(e, "min_year")))
          loot << ("\nHistory year: " + (history_year = grab_text(e, "year")))
          loot << "\n\n\n"

          print_line("\n")
          print_status("Company History for year #{history_year}\n--------------------------------")
          print_status("CorpWatch ID: " + cwid)
          print_status("Central Index Key: " + cik)
          print_status("IRS number: " + irsno)
          print_status("SIC Code: " + sic_code)
          print_status("Industry: " + industry)
          print_status("Sector: " + sector)
          print_status("SIC Sector: " + sic_sector)
          print_status("Source: " + source)
          print_status("Address: " + address)
          print_status("Country: " + country_code)
          print_status("Subdivision: " + subdiv_code)
          print_status("Top Parent ID: " + top_parent)
          print_status("Number of parents: " + num_parents)
          print_status("Number of children: " + num_children)
          print_status("Max lookup year: " + max_year)
          print_status("Min lookup year: " + min_year)
        }
      end
    end

    p = store_loot("corpwatch_api.#{datastore['CW_ID']}_info","text/plain",nil,loot,"company_#{datastore['CW_ID']}.txt","#{datastore["CW_ID"]} Specific Information")

    print_line()
    print_status("Saved in: #{p}")
  end

  def grab_text(e, name)
    (e.get_elements(name) && e.get_elements(name)[0] &&
    e.get_elements(name)[0].get_text ) ?
    e.get_elements(name)[0].get_text.to_s : ""
  end

end
