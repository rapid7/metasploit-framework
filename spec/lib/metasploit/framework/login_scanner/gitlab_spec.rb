require 'spec_helper'
require 'metasploit/framework/login_scanner/gitlab'

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
RSpec.describe Metasploit::Framework::LoginScanner::GitLab do
=======
describe Metasploit::Framework::LoginScanner::GitLab do
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
describe Metasploit::Framework::LoginScanner::GitLab do
>>>>>>> origin/msf-complex-payloads
=======
describe Metasploit::Framework::LoginScanner::GitLab do
>>>>>>> origin/msf-complex-payloads

    it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
    it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
    it_behaves_like 'Metasploit::Framework::LoginScanner::HTTP'

end
