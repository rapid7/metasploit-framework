
require File.dirname(__FILE__) + '/spec_helper'

def test name, version, os, engine, engine_version, string
  it "should parse #{name} #{version} on #{os} with engine #{engine} #{engine_version}" do
    agent = Agent.new string
    agent.name.should == name
    agent.os.should == os
    agent.engine.should == engine
    agent.version.should == version
    agent.engine_version.should == engine_version
  end
end

describe Agent do

  test :Safari, '4.0dp1', :'Windows XP',    :webkit, '526.9',    'Mozilla/5.0 (Windows; U; Windows NT 5.1; en) AppleWebKit/526.9 (KHTML, like Gecko) Version/4.0dp1 Safari/526.8'
  test :Safari, '4.0.3',  :'Windows Vista', :webkit, '531.9',    'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-us) AppleWebKit/531.9 (KHTML, like Gecko) Version/4.0.3 Safari/531.9'
  test :Safari, '4.0.2',  :'Windows 7',     :webkit, '532',      'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/532+ (KHTML, like Gecko) Version/4.0.2 Safari/530.19.1'
  test :Safari, '4.0.1',  :'OS X 10.5',     :webkit, '531.2',    'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_7; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/4.0.1 Safari/530.18'
  test :Safari, '4.0',    :'Windows Vista', :webkit, '528.16',   'Mozilla/5.0 (Windows; U; Windows NT 6.0; ru-RU) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16'
  test :Safari, '3.2.3',  :'Windows XP',    :webkit, '525.28.3', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; cs-CZ) AppleWebKit/525.28.3 (KHTML, like Gecko) Version/3.2.3 Safari/525.29'

  test :IE, '8.0',  :'Windows 7',    :msie, '8.0',  'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.2; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)'
  test :IE, '7.0b', :'Windows 2003', :msie, '7.0b', 'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)'
  test :IE, '6.0b', :'Windows XP',   :msie, '6.0b', 'Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)'
  test :IE, '6.0',  :'Windows XP',   :msie, '6.0',  'Mozilla/5.0 (Windows; U; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)'

  test :Opera, '9.99', :'Windows XP', :presto,  '9.9.9',    'Opera/9.99 (Windows NT 5.1; U; pl) Presto/9.9.9'
  test :Opera, '9.70', :Linux,        :gecko,   '20061208', 'Mozilla/5.0 (Linux i686 ; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.70'
  test :Opera, '9.64', :Linux,        :presto,  '2.1.1',    'Opera/9.64 (X11; Linux i686; U; Linux Mint; it) Presto/2.1.1'
  test :Opera, '9.00', :Wii,          :unknown,  nil,       'Opera/9.00 (Nintindo Wii; U; ; 103858; Wii Shop Channel/1.0; en)'

  test :Chrome, '4.0.202.2',  :Linux,           :webkit, '532.0',  'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/4.0.202.2 Safari/532.0'
  test :Chrome, '0.2.149.27', :'Windows 2003',  :webkit, '525.13', 'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.27 Safari/525.13'
  test :Chrome, '0.2.149.30', :'Windows Vista', :webkit, '525.13', 'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.30 Safari/525.13'

  test :Konqueror, '4.2',     :Linux, :khtml,     '4.2.4',    'Mozilla/5.0 (compatible; Konqueror/4.2; Linux; X11; x86_64) KHTML/4.2.4 (like Gecko) Fedora/4.2.4-2.fc11'
  test :Konqueror, '3.1-rc6', :Linux, :konqueror, '3.1-rc6', 'Mozilla/5.0 (compatible; Konqueror/3.1-rc6; i686 Linux; 20021105)'

  test :PS3, '2.00', :Playstation, :unknown, nil, 'Mozilla/5.0 (PLAYSTATION 3; 2.00)'
  test :PS3, '1.10', :Playstation, :unknown, nil, 'Mozilla/5.0 (PLAYSTATION 3; 1.10)'

  test :PSP, '2.00', :Playstation, :unknown, nil, 'PSP (PlayStation Portable); 2.00'
  test :PSP, '2.00', :Playstation, :unknown, nil, 'Mozilla/4.0 (PSP (PlayStation Portable); 2.00)'

  test :Firefox, '3.5', :Linux,         :gecko, '20090624',   'Mozilla/5.0 (X11;U; Linux i686; en-GB; rv:1.9.1) Gecko/20090624 Ubuntu/9.04 (jaunty) Firefox/3.5'
  test :Firefox, '3.5', :'Windows 7',   :gecko, '20090612',   'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1) Gecko/20090612 Firefox/3.5'
  test :Firefox, '3.1', :'Windows XP',  :gecko, '2009011606', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.6pre) Gecko/2009011606 Firefox/3.1'
  test :Firefox, '3.0', :Linux,         :gecko, '2008062315', 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9) Gecko/2008062315 (Gentoo) Firefox/3.0'
  test :Firefox, '2.0', :Linux,         :gecko, '20061202',   'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1) Gecko/20061202 Firefox/2.0'

end
