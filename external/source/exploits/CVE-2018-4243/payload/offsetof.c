unsigned off_p_pid = 0x10;               // proc_t::p_pid
unsigned off_task = 0x18;                // proc_t::task
unsigned off_p_uid = 0x30;               // proc_t::p_uid
unsigned off_p_gid = 0x34;               // proc_t::p_uid
unsigned off_p_ruid = 0x38;              // proc_t::p_uid
unsigned off_p_rgid = 0x3c;              // proc_t::p_uid
unsigned off_p_ucred = 0x100;            // proc_t::p_ucred
unsigned off_p_csflags = 0x2a8;          // proc_t::p_csflags
unsigned off_p_comm = 0x268;             // proc_t::p_comm
unsigned off_p_textvp = 0x248;           // proc_t::p_textvp
unsigned off_p_textoff = 0x250;          // proc_t::p_textoff
unsigned off_p_cputype = 0x2c0;          // proc_t::p_cputype
unsigned off_p_cpu_subtype = 0x2c4;      // proc_t::p_cpu_subtype

unsigned off_itk_self = 0xD8;            // task_t::itk_self (convert_task_to_port)
unsigned off_itk_sself = 0xE8;           // task_t::itk_sself (task_get_special_port)
unsigned off_itk_bootstrap = 0x2b8;      // task_t::itk_bootstrap (task_get_special_port)
unsigned off_itk_space = 0x308;          // task_t::itk_space

unsigned off_ip_mscount = 0x9C;          // ipc_port_t::ip_mscount (ipc_port_make_send)
unsigned off_ip_srights = 0xA0;          // ipc_port_t::ip_srights (ipc_port_make_send)
unsigned off_ip_kobject = 0x68;          // ipc_port_t::ip_kobject

unsigned off_special = 2 * sizeof(long); // host::special
unsigned off_ipc_space_is_table = 0x20;  // ipc_space::is_table?..

unsigned off_ucred_cr_uid = 0x18;        // ucred::cr_uid
unsigned off_ucred_cr_ruid = 0x1c;       // ucred::cr_ruid
unsigned off_ucred_cr_svuid = 0x20;      // ucred::cr_svuid
unsigned off_ucred_cr_ngroups = 0x24;    // ucred::cr_ngroups
unsigned off_ucred_cr_groups = 0x28;     // ucred::cr_groups
unsigned off_ucred_cr_rgid = 0x68;       // ucred::cr_rgid
unsigned off_ucred_cr_svgid = 0x6c;      // ucred::cr_svgid
unsigned off_ucred_cr_label = 0x78;      // ucred::cr_label

unsigned off_amfi_slot = 0x8;
unsigned off_sandbox_slot = 0x10;

unsigned off_v_type = 0x70;              // vnode::v_type
unsigned off_v_id = 0x74;                // vnode::v_id
unsigned off_v_ubcinfo = 0x78;           // vnode::v_ubcinfo
unsigned off_v_flags = 0x54;             // vnode::v_flags

unsigned off_ubcinfo_csblobs = 0x50;     // ubc_info::csblobs

unsigned off_csb_cputype = 0x8;          // cs_blob::csb_cputype
unsigned off_csb_flags = 0x12;           // cs_blob::csb_flags
unsigned off_csb_base_offset = 0x16;     // cs_blob::csb_base_offset
unsigned off_csb_entitlements_offset = 0x90; // cs_blob::csb_entitlements
unsigned off_csb_signer_type = 0xA0;     // cs_blob::csb_signer_type
unsigned off_csb_platform_binary = 0xA4; // cs_blob::csb_platform_binary
unsigned off_csb_platform_path = 0xA8;   // cs_blob::csb_platform_path
unsigned off_csb_cd = 0x80;              // cs_blob::csb_cd

unsigned off_t_flags = 0x3a0; // task::t_flags

unsigned off_v_mount = 0xd8;             // vnode::v_mount
unsigned off_v_specinfo = 0x78;          // vnode::v_specinfo
unsigned off_specflags = 0x10;
unsigned off_mnt_flag = 0x70;            // mount::mnt_flag
unsigned off_mnt_data = 0x8f8;           // mount::mnt_data

