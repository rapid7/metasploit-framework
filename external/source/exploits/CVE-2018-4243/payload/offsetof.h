
extern unsigned off_p_pid;
extern unsigned off_task;
extern unsigned off_p_uid;
extern unsigned off_p_gid;
extern unsigned off_p_ruid;
extern unsigned off_p_rgid;
extern unsigned off_p_ucred;
extern unsigned off_p_csflags;
extern unsigned off_p_comm;

extern unsigned off_itk_self;
extern unsigned off_itk_sself;
extern unsigned off_itk_bootstrap;
extern unsigned off_itk_space;
extern unsigned off_ip_mscount;
extern unsigned off_ip_srights;
extern unsigned off_ip_kobject;
extern unsigned off_p_textvp;
extern unsigned off_p_textoff;
extern unsigned off_p_cputype;
extern unsigned off_p_cpu_subtype;
extern unsigned off_special;
extern unsigned off_ipc_space_is_table;

extern unsigned off_ucred_cr_uid;
extern unsigned off_ucred_cr_ruid;
extern unsigned off_ucred_cr_gid;
extern unsigned off_ucred_cr_rgid;
extern unsigned off_ucred_cr_svgid;
extern unsigned off_ucred_cr_groups;
extern unsigned off_ucred_cr_ngroups;
extern unsigned off_ucred_cr_svuid;
extern unsigned off_ucred_cr_label;

extern unsigned off_amfi_slot;
extern unsigned off_sandbox_slot;

extern unsigned off_v_type;
extern unsigned off_v_id;
extern unsigned off_v_ubcinfo;
extern unsigned off_v_flags;

extern unsigned off_ubcinfo_csblobs;

extern unsigned off_csb_cputype;
extern unsigned off_csb_flags;
extern unsigned off_csb_base_offset;
extern unsigned off_csb_entitlements_offset;
extern unsigned off_csb_signer_type;
extern unsigned off_csb_platform_binary;
extern unsigned off_csb_platform_path;
extern unsigned off_csb_cd;

extern unsigned off_t_flags;

extern unsigned off_v_mount;
extern unsigned off_v_specinfo;
extern unsigned off_specflags;
extern unsigned off_mnt_flag;
extern unsigned off_mnt_data;

#define	CS_VALID		0x0000001	/* dynamically valid */
#define CS_ADHOC		0x0000002	/* ad hoc signed */
#define CS_GET_TASK_ALLOW	0x0000004	/* has get-task-allow entitlement */
#define CS_INSTALLER		0x0000008	/* has installer entitlement */

#define	CS_HARD			0x0000100	/* don't load invalid pages */
#define	CS_KILL			0x0000200	/* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION	0x0000400	/* force expiration checking */
#define CS_RESTRICT		0x0000800	/* tell dyld to treat restricted */
#define CS_ENFORCEMENT		0x0001000	/* require enforcement */
#define CS_REQUIRE_LV		0x0002000	/* require library validation */
#define CS_ENTITLEMENTS_VALIDATED	0x0004000

#define	CS_ALLOWED_MACHO	0x00ffffe

#define CS_EXEC_SET_HARD	0x0100000	/* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL	0x0200000	/* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT	0x0400000	/* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_SET_INSTALLER	0x0800000	/* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED		0x1000000	/* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM	0x2000000	/* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY	0x4000000	/* this is a platform binary */
#define CS_PLATFORM_PATH	0x8000000	/* platform binary by the fact of path (osx only) */

#define CS_DEBUGGED         0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
#define CS_SIGNED         0x20000000  /* process has a signature (may have gone invalid) */
#define CS_DEV_CODE         0x40000000  /* code is dev signed, cannot be loaded into prod signed code (will go away with rdar://problem/28322552) */

