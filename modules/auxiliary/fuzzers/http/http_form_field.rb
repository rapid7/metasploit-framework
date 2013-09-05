##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

##
#
# Tip : run "show advanced" for more options
#
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'HTTP Form Field Fuzzer',
      'Description'    => %q{
        This module will grab all fields from a form,
        and launch a series of POST actions, fuzzing the contents
        of the form fields. You can optionally fuzz headers too
        (option is enabled by default)
      },
      'Author'  => [
        'corelanc0d3r',
        'Paulino Calderon <calderon[at]websec.mx>' #Added cookie handling
        ],
      'License'       => MSF_LICENSE,
      'References'    =>
        [
          ['URL','http://www.corelan.be:8800/index.php/2010/11/12/metasploit-module-http-form-field-fuzzer'],
        ]
      ))

    register_options(
      [
        OptString.new('URL', [ false, "The URL that contains the form", "/"]),
        OptString.new('FORM', [ false, "The name of the form to use. Leave empty to fuzz all forms","" ] ),
        OptString.new('FIELDS', [ false, "Name of the fields to fuzz. Leave empty to fuzz all fields","" ] ),
        OptString.new('ACTION', [ false, "Form action full URI. Leave empty to autodetect","" ] ),
        OptInt.new('STARTSIZE', [ true, "Fuzzing string startsize.",1000]),
        OptInt.new('ENDSIZE', [ true, "Max Fuzzing string size.",40000]),
        OptInt.new('STEPSIZE', [ true, "Increment fuzzing string each attempt.",1000]),
        OptInt.new('TIMEOUT', [ true, "Number of seconds to wait for response on GET or POST",15]),
        OptInt.new('DELAY', [ true, "Number of seconds to wait between 2 actions",0]),
        OptInt.new('STOPAFTER', [ false, "Stop after x number of consecutive errors",2]),
        OptBool.new('CYCLIC', [ true, "Use Cyclic pattern instead of A's (fuzzing payload).",true]),
        OptBool.new('FUZZHEADERS', [ true, "Fuzz headers",true]),
        OptString.new('HEADERFIELDS', [ false, "Name of the headerfields to fuzz. Leave empty to fuzz all fields","" ] ),
        OptString.new('TYPES', [ true, "Field types to fuzz","text,password,inputtextbox"]),
        OptString.new('CODE', [ true, "Response code(s) indicating OK", "200,301,302,303" ] ),
        OptBool.new('HANDLECOOKIES', [ true, "Appends cookies with every request.",false])
      ], self.class )
  end

  def init_vars
    proto = "http://"
    if datastore['SSL']
      proto = "https://"
    end

    @send_data = {
        :uri => '',
        :version => '1.1',
        :method => 'POST',
        :headers => {
          'Content-Length' => 100,
          'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language' => 'en-us,en;q=0.5',
          'Accept-Encoding' => 'gzip,deflate',
          'Accept-Charset' => 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
          'Keep-Alive' => '300',
          'Connection' => 'keep-alive',
          'Referer' => proto + datastore['RHOST'] + ":" + datastore['RPORT'].to_s,
          'Content-Type' => 'application/x-www-form-urlencoded'
        }
      }
    @get_data_headers = {
        'Referer' => proto + datastore['RHOST'] + ":" + datastore['RPORT'].to_s,
      }
  end

  def init_fuzzdata
    @fuzzsize = datastore['STARTSIZE']
    @endsize = datastore['ENDSIZE']
    set_fuzz_payload()
    @nrerrors = 0
  end

  def incr_fuzzsize
    @stepsize = datastore['STEPSIZE'].to_i
    @fuzzsize = @fuzzsize + @stepsize
  end

  def set_fuzz_payload
    if datastore['CYCLIC']
      @fuzzdata = Rex::Text.pattern_create(@fuzzsize)
    else
      @fuzzdata = "A" * @fuzzsize
    end
  end

  def is_error_code(code)
    okcode = false
    checkcodes = datastore['CODE'].split(",")
    checkcodes.each do | testcode |
      testcode = testcode.upcase.gsub(" ","")
      if testcode == code.to_s().upcase.gsub(" ","")
        okcode = true
      end
    end
    return okcode
  end

  def fuzz_this_field(fieldname,fieldtype)
    fuzzcommands = datastore['FIELDS'].split(",")
    fuzzme = 0
    if fuzzcommands.size > 0
      fuzzcommands.each do |thiscmd|
        thiscmd = thiscmd.strip
        if ((fieldname.upcase == thiscmd.upcase) || (thiscmd == "")) && (fuzzme == 0)
          fuzzme = 1
        end
      end
    else
      fuzztypes = datastore['TYPES'].split(",")
      fuzztypes.each do | thistype |
        if (fieldtype.upcase.strip == thistype.upcase.strip)
          fuzzme = 1
        end
      end
    end
    if fuzzme == 1
      set_fuzz_payload()
    end
    return fuzzme
  end

  def fuzz_this_headerfield(fieldname)
    fuzzheaderfields = datastore['HEADERFIELDS'].split(",")
    fuzzme = 0
    if fuzzheaderfields.size > 0
      fuzzheaderfields.each do |thisfield|
        thisfield = thisfield.strip
        if ((fieldname.upcase == thisfield.upcase) || (thisfield == "")) && (fuzzme == 0)
          fuzzme = 1
        end
      end
    else
      fuzzme = 1
    end
    if fuzzme == 1
      set_fuzz_payload()
    end
    return fuzzme
  end

  def do_fuzz_headers(form,headers)
    headercnt = 0
    datastr = ""
    form[:fields].each do | thisfield |
      normaldata = "blah&"
      if thisfield[:value]
        if thisfield[:value] != ""
          normaldata = thisfield[:value].strip + "&"
        end
      end
      datastr << thisfield[:name].downcase.strip + "=" + normaldata
    end
    if datastr.length > 0
      datastr=datastr[0,datastr.length-1] + "\r\n"
    else
      datastr = "\r\n"
    end
    #first, check the original header fields and add some others - just for fun
    myheaders = @send_data[:headers]
    mysendheaders = @send_data[:headers].dup
    #get or post ?
    mysendheaders[:method] = form[:method].upcase
    myheaders.each do | thisheader |
      if not headers[thisheader[0]]
        #add header if needed
        mysendheaders[thisheader[0]]= thisheader[1]
      end
    end
    nrheaderstofuzz = mysendheaders.size
    mysendheaders.each do | thisheader|
      @fuzzheader = mysendheaders.dup
      @nrerrors = 0
      fuzzpacket = @send_data.dup
      fuzzpacket[:method] = mysendheaders[:method]
      headername = thisheader[0]
      if fuzz_this_headerfield(headername.to_s().upcase) == 1
        print_status("    - Fuzzing header '#{headername}' (#{headercnt+1}/#{nrheaderstofuzz})")
        init_fuzzdata()
        while @fuzzsize <= @endsize+1
          @fuzzheader[headername] = @fuzzdata
          fuzzpacket[:headers] = @fuzzheader
          response = send_fuzz(fuzzpacket,datastr)
          if not process_response(response,headername,"header")
            @fuzzsize = @endsize+2
          end
          if datastore['DELAY'] > 0
            print_status("      (Sleeping for #{datastore['DELAY']} seconds...)")
            select(nil,nil,nil,datastore['DELAY'])
          end
          incr_fuzzsize()
        end
      else
        print_status("    - Skipping header '#{headername}' (#{headercnt+1}/#{nrheaderstofuzz})")
      end
      headercnt += 1
    end
  end

  def do_fuzz_field(form,field)
    fieldstofuzz = field.downcase.strip.split(",")
    @nrerrors = 0
    while @fuzzsize <= @endsize+1
      allfields = form[:fields]
      datastr = ""
      normaldata = ""
      allfields.each do | thisfield |
        dofuzzthis = false
        if thisfield[:name]
          fieldstofuzz.each do | fuzzthis |
            if fuzzthis
              if (thisfield[:name].downcase.strip == fuzzthis.downcase.strip)
                dofuzzthis = true
              end
            end
          end
          if thisfield[:value]
            normaldata = thisfield[:value].strip
          else
            normaldata = ""
          end
          if (dofuzzthis)
            datastr << thisfield[:name].downcase.strip + "=" + @fuzzdata + "&"
          else
            datastr << thisfield[:name].downcase.strip + "=" + normaldata + "&"
          end
        end
      end
      datastr=datastr[0,datastr.length-1]
      @send_data[:uri] = form[:action]
      @send_data[:uri] = "/#{form[:action]}" if @send_data[:uri][0,1] != '/'

      @send_data[:method] = form[:method].upcase
      response = send_fuzz(@send_data,datastr)
      if not process_response(response,field,"field")
        return
      end
      if datastore['DELAY'] > 0
        print_status("      (Sleeping for #{datastore['DELAY']} seconds...)")
        select(nil,nil,nil,datastore['DELAY'])
      end
    end
  end

  def process_response(response,field,type)
    if response == nil
      print_error("      No response - #{@nrerrors+1} / #{datastore['STOPAFTER']} - fuzzdata length : #{@fuzzsize}")
      if @nrerrors+1 >= datastore['STOPAFTER']
        print_status("      *!* No response : #{type} #{field} | fuzzdata length : #{@fuzzsize}")
        return false
      else
        @nrerrors = @nrerrors + 1
      end
    else
      okcode = is_error_code(response.code)
      if okcode
          @nrerrors = 0
          incr_fuzzsize()
      end
      if not okcode and @nrerrors+1 >= datastore['STOPAFTER']
        print_status("      *!* Error response code #{response.code} | #{type} #{field} | fuzzdata length #{@fuzzsize}")
        return false
      else
        @nrerrors = @nrerrors + 1
      end
    end
    return true
  end

  def send_fuzz(postdata,data)
    header = postdata[:headers]
    response = send_request_raw({
        'uri' => postdata[:uri],
        'version' => postdata[:version],
        'method' => postdata[:method],
        'headers' => header,
        'data' => data
        }, datastore['TIMEOUT'])
    return response
  end

  def get_field_val(input)
    tmp = input.split(/\=/)
    #get delimeter
    tmp2 = tmp[1].strip
    delim = tmp2[0,1]
    if delim != "'" && delim != '"'
      delim = ""
    end
    tmp3 = tmp[1].split(/>/)
    tmp4 = tmp3[0].gsub(delim,"")
    return tmp4
  end

  def get_form_data(body)
    print_status("Enumerating form data")
    body = body.gsub("\r","")
    body = body.gsub("\n","")
    bodydata = body.downcase.split(/<form/)
    #we need part after <form
    totalforms = bodydata.size - 1
    print_status("    Number of forms : #{totalforms}")
    formcnt = 0
    formidx = 1
    forms = []
    while formcnt < totalforms
      fdata = bodydata[formidx]
      print_status("    - Enumerating form ##{formcnt+1}")
      data = fdata.downcase.split(/<\/form>/)
      #first, get action and name
      formdata = data[0].downcase.split(/>/)
      subdata = formdata[0].downcase.split(/ /)
      namefound = false
      actionfound = false
      idfound = false
      actionname = ""
      formname = ""
      formid = ""
      formmethod = "post"
      subdata.each do | thisfield |
        if thisfield.match(/^name=/) and not namefound
          formname = get_field_val(thisfield)
          namefound = true
        end
        if thisfield.match(/^id=/) and not idfound
          formid = get_field_val(thisfield)
          idfound = true
        end
        if thisfield.match(/^method=/)
          formmethod = get_field_val(thisfield)
        end
        if thisfield.match(/^action=/) and not actionfound
          actionname = get_field_val(thisfield)
          if (actionname.length < datastore['URL'].length) and (datastore['URL'].downcase.index(actionname.downcase).to_i() > -1)
            actionname = datastore['URL']
          end
          actionfound = true
        end
      end
      if datastore['ACTION'].length > 0
        actionname = datastore['ACTION']
        actionfound = true
      end

      if formname == "" and formid != ""
        formname = formid
      end
      if formid == "" and formname != ""
        formid = formname
      end
      if formid == "" and formname == ""
        formid = "noname_" + (formcnt+1).to_s()
        formname = formid
      end
      idfound = true
      namefound = true

      formfields = []
      #input boxes
      fieldtypemarks = [ '<input', '<select' ]
      fieldtypemarks.each do | currfieldmark |
        formfieldcnt=0
        if (namefound or idfound) and actionfound
          # get fields in current form - data[0]
          subdata = data[0].downcase.split(currfieldmark)
          skipflag=0
          if subdata.size > 1
            subdata.each do | thisinput |
              if skipflag == 1
                #first, find the delimeter
                fielddata = thisinput.downcase.split(/>/)
                fields = fielddata[0].split(/ /)
                fieldname = ""
                fieldtype = ""
                fieldvalue = ""
                fieldmethod = "post"
                fieldid = ""
                fields.each do | thisfield |
                  if thisfield.match(/^type=/)
                    fieldtype = get_field_val(thisfield)
                  end
                  if currfieldmark == "<select" and thisfield.match(/^class=/)
                    fieldtype = get_field_val(thisfield)
                  end
                  if thisfield.match(/^name=/)
                    fieldname = get_field_val(thisfield)
                  end
                  if thisfield.match(/^id=/)
                    fieldid = get_field_val(thisfield)
                  end
                  if thisfield.match(/^value=/)
                    #special case
                    location = fielddata[0].index(thisfield)
                    delta = fielddata[0].size - location
                    remaining = fielddata[0][location,delta]
                    tmp = remaining.strip.split(/\=/)
                    if tmp.size > 1
                      delim = tmp[1][0,1]
                      tmp2 = tmp[1].split(delim)
                      fieldvalue = tmp2[1]
                    end
                  end
                end
                if fieldname == "" and fieldid != ""
                  fieldname = fieldid
                end
                if fieldid == "" and fieldname != ""
                  fieldid = fieldname
                end
                print_status("      Field : #{fieldname}, type #{fieldtype}")
                if fieldid != ""
                  formfields << {
                    :id => fieldid,
                    :name => fieldname,
                    :type => fieldtype,
                    :value => fieldvalue
                  }
                  formfieldcnt += 1
                end
              else
                skipflag += 1
              end
            end
          end
        end
      end
      print_status("      Nr of fields in form '#{formname}' : #{formfields.size}")
      # store in multidimensional array
      forms << {
        :name => formname,
        :id => formid,
        :action => actionname,
        :method => formmethod,
        :fields => formfields
      }
      formidx = formidx + 1
      formcnt += 1
    end
    if forms.size > 0
      print_status("    Forms : ")
    end
    forms.each do | thisform |
      print_status("     - Name : #{thisform[:name]}, ID : #{thisform[:id]}, Action : #{thisform[:action]}, Method : #{thisform[:method]}")
    end
    return forms
  end
  def extract_cookie(body)
    return body["Set-Cookie"]
  end
  def set_cookie(cookie)
    @get_data_headers["Cookie"]=cookie
    @send_data[:headers]["Cookie"]=cookie
  end
  def run
    init_fuzzdata()
    init_vars()

    print_status("Grabbing webpage #{datastore['URL']} from #{datastore['RHOST']}")
    response = send_request_raw(
    {
      'uri' => normalize_uri(datastore['URL']),
      'version' => '1.1',
      'method' => 'GET',
      'headers' => @get_data_headers

    }, datastore['TIMEOUT'])
    if response == nil
      print_error("No response")
      return
    end
    if datastore['HANDLECOOKIES']
      cookie = extract_cookie(response.headers)
      set_cookie(cookie)
      print_status("Set cookie:#{cookie}")
      print_status("Grabbing webpage #{datastore['URL']} from #{datastore['RHOST']} using cookies")

      response = send_request_raw(
      {
        'uri' => normalize_uri(datastore['URL']),
        'version' => '1.1',
        'method' => 'GET',
        'headers' => @get_data_headers
      }, datastore['TIMEOUT'])
    end
    if response == nil
      print_error("No response")
      return
    end
    print_status("Code : #{response.code}")
    okcode = is_error_code(response.code)
    if not okcode
      print_error("Server replied with error code. Check URL or set CODE to another value, and try again.")
      return
    end
    if response.body
      formfound = response.body.downcase.index("<form")
      if formfound
        formdata = get_form_data(response.body)
        #fuzz !
        #for each form that needs to be fuzzed
        formdata.each do | thisform |
          if thisform[:name].length > 0
            if ((datastore['FORM'].strip == "") || (datastore['FORM'].upcase.strip == thisform[:name].upcase.strip)) && (thisform[:fields].size > 0)
              print_status("Fuzzing fields in form #{thisform[:name].upcase.strip}")
              #for each field in this form, fuzz one field at a time
              formfields = thisform[:fields]
              formfields.each do | thisfield |
                if thisfield[:name]
                  if fuzz_this_field(thisfield[:name],thisfield[:type]) == 1
                    print_status("    - Fuzzing field #{thisfield[:name]}")
                    do_fuzz_field(thisform,thisfield[:name])
                    init_fuzzdata()
                  end
                end
              end
              print_status("Done fuzzing fields in form #{thisform[:name].upcase.strip}")
            end
            #fuzz headers ?
            if datastore['FUZZHEADERS'] == true
              print_status("Fuzzing header fields")
              do_fuzz_headers(thisform,response.headers)
            end
          end
        end

      else
        print_error("No form found in response body")
        print_status(response.body)
        return
      end
    else
      print_error("No response data")
    end

  end
end
