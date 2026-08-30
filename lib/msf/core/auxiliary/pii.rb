# -*- coding: binary -*-

module Msf

###
#
# This module provides methods for time-limited modules
#
###

module Auxiliary::PII

#
def initialize(info = {})
  super

  register_options(
    [
      OptInt.new('ENTRIES', [ false, "PII Entry Count", 1000]),
      OptString.new('EMAIL_DOMAIN', [false, "Email Domain", "localhost.localdomain"])
    ], Auxiliary::PII)

end

#
# The command handler when launched from the console
#
def create_acct()
  iin = [40,41,42,43,44,45,51,52,53,54,55]
  acct = iin[rand(9)].to_s

  while acct.length < 16
    acct = acct.concat("#{rand(9).to_s}")
  end
  cvv = rand(899)+100
  "#{acct}/#{cvv.to_s}"
end

def create_ssn
  aaa = rand(5)+734
  gg = rand(89)+10
  sss = rand(8999)+1000
  "#{aaa.to_s}-#{gg.to_s}-#{sss.to_s}"
end

def create_dob
  "#{rand(11)+1}-#{rand(27)+1}-#{rand(30)+1960}"
end

def create_pw
  list = ['123456','password','12345678','qwerty','abc123','111111','letmein','trustno1','superman',
    'iloveyou','sunshine','1234','princess','starwars','princess','nintendo','computer','Password',
    'passw0rd','michael','football','whatever','shadow','pokemon','666666','forgetyou','blahblah',
    'cowboys','yankees','ravens','orioles','pirates','dabears','tiger','fairies','sushi','money',
    'killzone','sandbox','rotflmao','subway','knicks','lakers','chargers','kermit','pigskin','baseball']
  list[rand(list.length-1)]
end

def luhnCheck(ccNumber)
  ccNumber = ccNumber.gsub(/\D/, '')
  cardLength = ccNumber.length
  parity = cardLength % 2
  sum = 0
  for i in 0...cardLength
    digit = ccNumber[i] - 48
    if i % 2 == parity
      digit = digit * 2
    end
    if digit > 9
      digit = digit - 9
    end
    sum = sum + digit
  end
  return (sum % 10)
end

def create_pii
  pii = ''
  i = 0
  fnames = ['MICHAEL','JASON','JOHN','JAMES','ROBERT','DAVID','DANIEL','ERIC','RYAN','CHRISTOPHER','WILLIAM',
    'JESSICA','KIMBERLY','COURTNEY','ELIZABETH','SUSAN','MICHELLE','JENNIFER','SARAH','LAUREN','AMANDA',
    'SHAWN','HUGH','PAUL','IAN','GARY','TRACY','ELAINE','JACKIE','AARON','SANDRA','DARREN','STEVEN',
    'ALEX','ELLEN','ALLEN','RONALD','GARRETT','JARED','RITA','JAYNE','JACOB','HAROLD','BAILEY']

  lnames = ['BROWN','SMITH','JOHNSON','JACKSON','ROBINSON','JONES','MOORE','HAYES','ABRAHAM','SCOTT','EVANS',
    'MCINTYRE','KNOX','HENDERSON','MALONE','PERRY','DOTSON','STEWART','MCDONALD','HAYWOOD','LOGAN',
    'PATTERSON','RAINEY','POTTS','KILBURN','BANKS','PETERSON','STOTT','KING','MCQEEN','TONGE','BLACK',
    'BROWN','BLACKBURN','WOODS','DAVIES','PAYTON','NICHOLSON','ROSE','ROBERTS','BIRD','FORD','HARRISON',
    'NIXON','CLINTON','REAGAN','BUTLER','DUKES','CARTER','WASHINGTON','GRANT','SMART']

  while i < datastore['ENTRIES']
    fname = fnames[rand(fnames.length-1)]
    lname = lnames[rand(lnames.length-1)]
    new_acct = create_acct()
    ssn = create_ssn()
    pw = create_pw()
    dob = create_dob()
    pii << "#{new_acct}/#{lname}/#{fname}/#{dob}/#{ssn}/#{fname}.#{lname}@metasploit.org/#{pw}\n"
    i += 1
  end
  pii
end

end
end
