##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB
  include Msf::Exploit::Remote::SMB::Authenticated
  include Msf::Exploit::Remote::DCERPC

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'SMB Session Pipe DCERPC Auditor',
            'Description' => 'Determine what DCERPC services are accessible over a SMB pipe',
            'Author'      => 'hdm',
            'License'     => MSF_LICENSE
        )
    )

    deregister_options('RPORT', 'RHOST')
    register_options(
      [
        OptString.new('SMBPIPE', [ true,  "The pipe name to use (BROWSER)", 'BROWSER']),
      ], self.class)
  end

  @@target_uuids = [
    [ '00000131-0000-0000-c000-000000000046', '0.0' ],
    [ '00000134-0000-0000-c000-000000000046', '0.0' ],
    [ '00000136-0000-0000-c000-000000000046', '0.0' ],
    [ '00000143-0000-0000-c000-000000000046', '0.0' ],
    [ '000001a0-0000-0000-c000-000000000046', '0.0' ],
    [ '04fcb220-fcfd-11cd-bec8-00aa0047ae4e', '1.0' ],
    [ '06bba54a-be05-49f9-b0a0-30f790261023', '1.0' ],
    [ '0767a036-0d22-48aa-ba69-b619480f38cb', '1.0' ],
    [ '0a5a5830-58e0-11ce-a3cc-00aa00607271', '1.0' ],
    [ '0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53', '1.0' ],
    [ '0b0a6584-9e0f-11cf-a3cf-00805f68cb1b', '1.0' ],
    [ '0b0a6584-9e0f-11cf-a3cf-00805f68cb1b', '1.1' ],
    [ '0b6edbfa-4a24-4fc6-8a23-942b1eca65d1', '1.0' ],
    [ '0c821d64-a3fc-11d1-bb7a-0080c75e4ec1', '1.0' ],
    [ '0d72a7d4-6148-11d1-b4aa-00c04fb66ea0', '1.0' ],
    [ '0da5a86c-12c2-4943-30ab-7f74a813d853', '1.0' ],
    [ '0e4a0156-dd5d-11d2-8c2f-00c04fb6bcde', '1.0' ],
    [ '1088a980-eae5-11d0-8d9b-00a02453c337', '1.0' ],
    [ '10f24e8e-0fa6-11d2-a910-00c04f990f3b', '1.0' ],
    [ '11220835-5b26-4d94-ae86-c3e475a809de', '1.0' ],
    [ '12345678-1234-abcd-ef00-0123456789ab', '1.0' ],
    [ '12345678-1234-abcd-ef00-01234567cffb', '1.0' ],
    [ '12345778-1234-abcd-ef00-0123456789ab', '0.0' ],
    [ '12345778-1234-abcd-ef00-0123456789ac', '1.0' ],
    [ '12b81e99-f207-4a4c-85d3-77b42f76fd14', '1.0' ],
    [ '12d4b7c8-77d5-11d1-8c24-00c04fa3080d', '1.0' ],
    [ '12e65dd8-887f-41ef-91bf-8d816c42c2e7', '1.0' ],
    [ '130ceefb-e466-11d1-b78b-00c04fa32883', '2.0' ],
    [ '1453c42c-0fa6-11d2-a910-00c04f990f3b', '1.0' ],
    [ '1544f5e0-613c-11d1-93df-00c04fd7bd09', '1.0' ],
    [ '16e0cf3a-a604-11d0-96b1-00a0c91ece30', '1.0' ],
    [ '16e0cf3a-a604-11d0-96b1-00a0c91ece30', '2.0' ],
    [ '17fdd703-1827-4e34-79d4-24a55c53bb37', '1.0' ],
    [ '18f70770-8e64-11cf-9af1-0020af6e72f4', '0.0' ],
    [ '1a9134dd-7b39-45ba-ad88-44d01ca47f28', '1.0' ],
    [ '1bddb2a6-c0c3-41be-8703-ddbdf4f0e80a', '1.0' ],
    [ '1be617c0-31a5-11cf-a7d8-00805f48a135', '3.0' ],
    [ '1cbcad78-df0b-4934-b558-87839ea501c9', '0.0' ],
    [ '1d55b526-c137-46c5-ab79-638f2a68e869', '1.0' ],
    [ '1ff70682-0a51-30e8-076d-740be8cee98b', '1.0' ],
    [ '201ef99a-7fa0-444c-9399-19ba84f12a1a', '1.0' ],
    [ '20610036-fa22-11cf-9823-00a0c911e5df', '1.0' ],
    [ '209bb240-b919-11d1-bbb6-0080c75e4ec1', '1.0' ],
    [ '2465e9e0-a873-11d0-930b-00a0c90ab17c', '3.0' ],
    [ '25952c5d-7976-4aa1-a3cb-c35f7ae79d1b', '1.0' ],
    [ '266f33b4-c7c1-4bd1-8f52-ddb8f2214ea9', '1.0' ],
    [ '28607ff1-15a0-8e03-d670-b89eec8eb047', '1.0' ],
    [ '2acb9d68-b434-4b3e-b966-e06b4b3a84cb', '1.0' ],
    [ '2eb08e3e-639f-4fba-97b1-14f878961076', '1.0' ],
    [ '2f59a331-bf7d-48cb-9e5c-7c090d76e8b8', '1.0' ],
    [ '2f5f3220-c126-1076-b549-074d078619da', '1.2' ],
    [ '2f5f6520-ca46-1067-b319-00dd010662da', '1.0' ],
    [ '2f5f6521-ca47-1068-b319-00dd010662db', '1.0' ],
    [ '2f5f6521-cb55-1059-b446-00df0bce31db', '1.0' ],
    [ '2fb92682-6599-42dc-ae13-bd2ca89bd11c', '1.0' ],
    [ '300f3532-38cc-11d0-a3f0-0020af6b0add', '1.2' ],
    [ '326731e3-c1c0-4a69-ae20-7d9044a4ea5c', '1.0' ],
    [ '333a2276-0000-0000-0d00-00809c000000', '3.0' ],
    [ '338cd001-2244-31f1-aaaa-900038001003', '1.0' ],
    [ '342cfd40-3c6c-11ce-a893-08002b2e9c6d', '0.0' ],
    [ '3473dd4d-2e88-4006-9cba-22570909dd10', '5.0' ],
    [ '3473dd4d-2e88-4006-9cba-22570909dd10', '5.1' ],
    [ '359e47c9-682e-11d0-adec-00c04fc2a078', '1.0' ],
    [ '367abb81-9844-35f1-ad32-98f038001003', '2.0' ],
    [ '369ce4f0-0fdc-11d3-bde8-00c04f8eee78', '1.0' ],
    [ '378e52b0-c0a9-11cf-822d-00aa0051e40f', '1.0' ],
    [ '386ffca4-22f5-4464-b660-be08692d7296', '1.0' ],
    [ '38a94e72-a9bc-11d2-8faf-00c04fa378ff', '1.0' ],
    [ '3919286a-b10c-11d0-9ba8-00c04fd92ef5', '0.0' ],
    [ '3ba0ffc0-93fc-11d0-a4ec-00a0c9062910', '1.0' ],
    [ '3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5', '1.0' ],
    [ '3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6', '1.0' ],
    [ '3dde7c30-165d-11d1-ab8f-00805f14db40', '1.0' ],
    [ '3f31c91e-2545-4b7b-9311-9529e8bffef6', '1.0' ],
    [ '3f77b086-3a17-11d3-9166-00c04f688e28', '1.0' ],
    [ '3f99b900-4d87-101b-99b7-aa0004007f07', '1.0' ],
    [ '3faf4738-3a21-4307-b46c-fdda9bb8c0d5', '1.0' ],
    [ '3faf4738-3a21-4307-b46c-fdda9bb8c0d5', '1.1' ],
    [ '41208ee0-e970-11d1-9b9e-00e02c064c39', '1.0' ],
    [ '412f241e-c12a-11ce-abff-0020af6e7a17', '0.2' ],
    [ '45776b01-5956-4485-9f80-f428f7d60129', '2.0' ],
    [ '45f52c28-7f9f-101a-b52b-08002b2efabe', '1.0' ],
    [ '469d6ec0-0d87-11ce-b13f-00aa003bac6c', '16.0' ],
    [ '4825ea41-51e3-4c2a-8406-8f2d2698395f', '1.0' ],
    [ '4a452661-8290-4b36-8fbe-7f4093a94978', '1.0' ],
    [ '4b112204-0e19-11d3-b42b-0000f81feb9f', '1.0' ],
    [ '4b324fc8-1670-01d3-1278-5a47bf6ee188', '0.0' ],
    [ '4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0' ],
    [ '4d9f4ab8-7d1c-11cf-861e-0020af6e7c57', '0.0' ],
    [ '4da1c422-943d-11d1-acae-00c04fc2aa3f', '1.0' ],
    [ '4f82f460-0e21-11cf-909e-00805f48a135', '4.0' ],
    [ '4fc742e0-4a10-11cf-8273-00aa004ae673', '3.0' ],
    [ '50abc2a4-574d-40b3-9d66-ee4fd5fba076', '5.0' ],
    [ '53e75790-d96b-11cd-ba18-08002b2dfead', '2.0' ],
    [ '56c8504c-4408-40fd-93fc-afd30f10c90d', '1.0' ],
    [ '57674cd0-5200-11ce-a897-08002b2e9c6d', '0.0' ],
    [ '57674cd0-5200-11ce-a897-08002b2e9c6d', '1.0' ],
    [ '5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc', '1.0' ],
    [ '5b5b3580-b0e0-11d1-b92d-0060081e87f0', '1.0' ],
    [ '5b821720-f63b-11d0-aad2-00c04fc324db', '1.0' ],
    [ '5c89f409-09cc-101a-89f3-02608c4d2361', '1.1' ],
    [ '5ca4a760-ebb1-11cf-8611-00a0245420ed', '1.0' ],
    [ '5cbe92cb-f4be-45c9-9fc9-33e73e557b20', '1.0' ],
    [ '5f54ce7d-5b79-4175-8584-cb65313a0e98', '1.0' ],
    [ '6099fc12-3eff-11d0-abd0-00c04fd91a4e', '3.0' ],
    [ '621dff68-3c39-4c6c-aae3-e68e2c6503ad', '1.0' ],
    [ '629b9f66-556c-11d1-8dd2-00aa004abd5e', '2.0' ],
    [ '629b9f66-556c-11d1-8dd2-00aa004abd5e', '3.0' ],
    [ '63fbe424-2029-11d1-8db8-00aa004abd5e', '1.0' ],
    [ '654976df-1498-4056-a15e-cb4e87584bd8', '1.0' ],
    [ '65a93890-fab9-43a3-b2a5-1e330ac28f11', '2.0' ],
    [ '68dcd486-669e-11d1-ab0c-00c04fc2dcd2', '1.0' ],
    [ '68dcd486-669e-11d1-ab0c-00c04fc2dcd2', '2.0' ],
    [ '69510fa1-2f99-4eeb-a4ff-af259f0f9749', '1.0' ],
    [ '6bffd098-0206-0936-4859-199201201157', '1.0' ],
    [ '6bffd098-a112-3610-9833-012892020162', '0.0' ],
    [ '6bffd098-a112-3610-9833-46c3f874532d', '1.0' ],
    [ '6bffd098-a112-3610-9833-46c3f87e345a', '1.0' ],
    [ '6e17aaa0-1a47-11d1-98bd-0000f875292e', '2.0' ],
    [ '708cca10-9569-11d1-b2a5-0060977d8118', '1.0' ],
    [ '76d12b80-3467-11d3-91ff-0090272f9ea3', '1.0' ],
    [ '76f226c3-ec14-4325-8a99-6a46348418af', '1.0' ],
    [ '77df7a80-f298-11d0-8358-00a024c480a8', '1.0' ],
    [ '7af5bbd0-6063-11d1-ae2a-0080c75e4ec1', '0.2' ],
    [ '7c44d7d4-31d5-424c-bd5e-2b3e1f323d22', '1.0' ],
    [ '7e048d38-ac08-4ff1-8e6b-f35dbab88d4a', '1.0' ],
    [ '7ea70bcf-48af-4f6a-8968-6a440754d5fa', '1.0' ],
    [ '7f9d11bf-7fb9-436b-a812-b2d50c5d4c03', '1.0' ],
    [ '811109bf-a4e1-11d1-ab54-00a0c91e9b45', '1.0' ],
    [ '8174bb16-571b-4c38-8386-1102b449044a', '1.0' ],
    [ '82273fdc-e32a-18c3-3f78-827929dc23ea', '0.0' ],
    [ '82980780-4b64-11cf-8809-00a004ff3128', '3.0' ],
    [ '82ad4280-036b-11cf-972c-00aa006887b0', '2.0' ],
    [ '83d72bf0-0d89-11ce-b13f-00aa003bac6c', '6.0' ],
    [ '83da7c00-e84f-11d2-9807-00c04f8ec850', '2.0' ],
    [ '86d35949-83c9-4044-b424-db363231fd0c', '1.0' ],
    [ '894de0c0-0d55-11d3-a322-00c04fa321a1', '1.0' ],
    [ '89742ace-a9ed-11cf-9c0c-08002be7ae86', '2.0' ],
    [ '8c7a6de0-788d-11d0-9edf-444553540000', '2.0' ],
    [ '8c7daf44-b6dc-11d1-9a4c-0020af6e7c57', '1.0' ],
    [ '8cfb5d70-31a4-11cf-a7d8-00805f48a135', '3.0' ],
    [ '8d09b37c-9f3a-4ebb-b0a2-4dee7d6ceae9', '1.0' ],
    [ '8d0ffe72-d252-11d0-bf8f-00c04fd9126b', '1.0' ],
    [ '8d9f4e40-a03d-11ce-8f69-08003e30051b', '0.0' ],
    [ '8d9f4e40-a03d-11ce-8f69-08003e30051b', '1.0' ],
    [ '8f09f000-b7ed-11ce-bbd2-00001a181cad', '0.0' ],
    [ '8fb6d884-2388-11d0-8c35-00c04fda2795', '4.1' ],
    [ '906b0ce0-c70b-1067-b317-00dd010662da', '1.0' ],
    [ '91ae6020-9e3c-11cf-8d7c-00aa00c091be', '0.0' ],
    [ '93149ca2-973b-11d1-8c39-00c04fb984f9', '0.0' ],
    [ '93f5ac6f-1a94-4bc5-8d1b-fd44fc255089', '1.0' ],
    [ '95958c94-a424-4055-b62b-b7f4d5c47770', '1.0' ],
    [ '975201b0-59ca-11d0-a8d5-00a0c90d8051', '1.0' ],
    [ '98fe2c90-a542-11d0-a4ef-00a0c9062910', '1.0' ],
    [ '99e64010-b032-11d0-97a4-00c04fd6551d', '3.0' ],
    [ '99fcfec4-5260-101b-bbcb-00aa0021347a', '0.0' ],
    [ '9b3195fe-d603-43d1-a0d5-9072d7cde122', '1.0' ],
    [ '9b8699ae-0e44-47b1-8e7f-86a461d7ecdc', '0.0' ],
    [ '9e8ee830-4459-11ce-979b-00aa005ffebe', '2.0' ],
    [ 'a002b3a0-c9b7-11d1-ae88-0080c75e4ec1', '1.0' ],
    [ 'a00c021c-2be2-11d2-b678-0000f87a8f8e', '1.0' ],
    [ 'a2d47257-12f7-4beb-8981-0ebfa935c407', '1.0' ],
    [ 'a398e520-d59a-4bdd-aa7a-3c1e0303a511', '1.0' ],
    [ 'a3b749b1-e3d0-4967-a521-124055d1c37d', '1.0' ],
    [ 'a4c2fd60-5210-11d1-8fc2-00a024cb6019', '1.0' ],
    [ 'a4f1db00-ca47-1067-b31e-00dd010662da', '1.0' ],
    [ 'a4f1db00-ca47-1067-b31f-00dd010662da', '0.0' ],
    [ 'a4f1db00-ca47-1067-b31f-00dd010662da', '0.81' ],
    [ 'aa177641-fc9b-41bd-80ff-f964a701596f', '1.0' ],
    [ 'aa411582-9bdf-48fb-b42b-faa1eee33949', '1.0' ],
    [ 'aae9ac90-ce13-11cf-919e-08002be23c64', '1.0' ],
    [ 'ae33069b-a2a8-46ee-a235-ddfd339be281', '1.0' ],
    [ 'afa8bd80-7d8a-11c9-bef4-08002b102989', '1.0' ],
    [ 'b58aa02e-2884-4e97-8176-4ee06d794184', '1.0' ],
    [ 'b97db8b2-4c63-11cf-bff6-08002be23f2f', '2.0' ],
    [ 'b9e79e60-3d52-11ce-aaa1-00006901293f', '0.2' ],
    [ 'bfa951d1-2f0e-11d3-bfd1-00c04fa3490a', '1.0' ],
    [ 'c33b9f46-2088-4dbc-97e3-6125f127661c', '1.0' ],
    [ 'c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0' ],
    [ 'c6f3ee72-ce7e-11d1-b71e-00c04fc3111a', '1.0' ],
    [ 'c8cb7687-e6d3-11d2-a958-00c04f682e16', '1.0' ],
    [ 'c9378ff1-16f7-11d0-a0b2-00aa0061426a', '1.0' ],
    [ 'c9ac6db5-82b7-4e55-ae8a-e464ed7b4277', '1.0' ],
    [ 'ce1334a5-41dd-40ea-881d-64326b23effe', '0.2' ],
    [ 'd049b186-814f-11d1-9a3c-00c04fc9b232', '1.1' ],
    [ 'd2d79dfa-3400-11d0-b40b-00aa005ff586', '1.0' ],
    [ 'd335b8f6-cb31-11d0-b0f9-006097ba4e54', '1.5' ],
    [ 'd3fbb514-0e3b-11cb-8fad-08002b1d29c3', '1.0' ],
    [ 'd6d70ef0-0e3b-11cb-acc3-08002b1d29c3', '1.0' ],
    [ 'd6d70ef0-0e3b-11cb-acc3-08002b1d29c4', '1.0' ],
    [ 'd7f9e1c0-2247-11d1-ba89-00c04fd91268', '5.0' ],
    [ 'd95afe70-a6d5-4259-822e-2c84da1ddb0d', '1.0' ],
    [ 'dd490425-5325-4565-b774-7e27d6c09c24', '1.0' ],
    [ 'e1af8308-5d1f-11c9-91a4-08002b14a0fa', '3.0' ],
    [ 'e248d0b8-bf15-11cf-8c5e-08002bb49649', '2.0' ],
    [ 'e33c0cc4-0482-101a-bc0c-02608c6ba218', '1.0' ],
    [ 'e3514235-4b06-11d1-ab04-00c04fc2dcd2', '4.0' ],
    [ 'e60c73e6-88f9-11cf-9af1-0020af6e72f4', '2.0' ],
    [ 'e67ab081-9844-3521-9d32-834f038001c0', '1.0' ],
    [ 'e76ea56d-453f-11cf-bfec-08002be23f2f', '2.0' ],
    [ 'ea0a3165-4834-11d2-a6f8-00c04fa346cc', '4.0' ],
    [ 'ec02cae0-b9e0-11d2-be62-0020afeddf63', '1.0' ],
    [ 'ecec0d70-a603-11d0-96b1-00a0c91ece30', '1.0' ],
    [ 'ecec0d70-a603-11d0-96b1-00a0c91ece30', '2.0' ],
    [ 'eff55e30-4ee2-11ce-a3c9-00aa00607271', '1.0' ],
    [ 'f50aac00-c7f3-428e-a022-a6b71bfb9d43', '1.0' ],
    [ 'f5cc59b4-4264-101a-8c59-08002b2f8426', '1.1' ],
    [ 'f5cc5a18-4264-101a-8c59-08002b2f8426', '56.0' ],
    [ 'f5cc5a7c-4264-101a-8c59-08002b2f8426', '21.0' ],
    [ 'f6beaff7-1e19-4fbb-9f8f-b89e2018337c', '1.0' ],
    [ 'f930c514-1215-11d3-99a5-00a0c9b61b04', '1.0' ],
    [ 'fc13257d-5567-4dea-898d-c6f9c48415a0', '1.0' ],
    [ 'fd7a0523-dc70-43dd-9b2e-9c5ed48225b1', '1.0' ],
    [ 'fdb3a030-065f-11d1-bb9b-00a024ea5525', '1.0' ],
    [ 'ffe561b8-bf15-11cf-8c5e-08002bb49649', '2.0' ]


]

  # Fingerprint a single host
  def run_host(ip)

    [[139, false], [445, true]].each do |info|

    datastore['RPORT'] = info[0]
    datastore['SMBDirect'] = info[1]

    begin
      connect()
      smb_login()

      @@target_uuids.each do |uuid|

        handle = dcerpc_handle(
          uuid[0], uuid[1],
          'ncacn_np', ["\\#{datastore['SMBPIPE']}"]
        )

        begin
          dcerpc_bind(handle)
          print_line("#{ip} - UUID #{uuid[0]} #{uuid[1]} OPEN VIA #{datastore['SMBPIPE']}")
          #Add Report
          report_note(
            :host	=> ip,
            :proto => 'tcp',
            :sname	=> 'smb',
            :port	=> rport,
            :type	=> "UUID #{uuid[0]} #{uuid[1]}",
            :data	=> "UUID #{uuid[0]} #{uuid[1]} OPEN VIA #{datastore['SMBPIPE']}"
          )
        rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
          # print_line("UUID #{uuid[0]} #{uuid[1]} ERROR 0x%.8x" % e.error_code)
        rescue ::Exception => e
          # print_line("UUID #{uuid[0]} #{uuid[1]} ERROR #{$!}")
        end
      end

      disconnect()

      return
    rescue ::Exception
      print_line($!.to_s)
    end
    end
  end


end
