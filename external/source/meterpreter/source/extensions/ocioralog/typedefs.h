//OCI structs
typedef struct  {
	char junk[140]; //Skip 17*8 + 4 bytes (140bytes)
	char *p_sess;  //Take the next 4 bytes as a pointer (points to the session structure)
} myOCISvcCtx;

typedef struct {
	unsigned char key[8]; //Take the first 8 bytes as the encryption key
	unsigned char cipherText[64]; //Take the rest of it as the encrypted password. Let's assume it is not more than 120bytes.
} DESEncrptedPassword;

typedef struct  {
	char junk[128]; //Skip 128 bytes
	char *p_username; //Take the next 4 bytes as a pointer (points to the usename string)
	char l_username; //Take the next bytes as a 1byte value (shows the lenght of the username)
	char DES_marker; //Take the next byte (must be 0x05) as a marker for DES encryption
	DESEncrptedPassword encryptedPassword; //Take the next ?? bytes until the first 0x00 byte as the crypted password
} myOCISession;

typedef struct  {
	char junk[160];
	char *p_stmt;
} myOCIStmt;
