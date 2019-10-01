ENTRY(Begin)
SECTIONS
{
	.text :
	{
		*(.text.Begin)
		*(.text.ExecutePayload)
		*(.text.GetProcAddressWithHash)
	}

}