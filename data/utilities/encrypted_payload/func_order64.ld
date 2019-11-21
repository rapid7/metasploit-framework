ENTRY(AlignRSP)
SECTIONS
{
	.text :
	{
    *(.text.AlignRSP)
		*(.text.ExecutePayload)
		*(.text.GetProcAddressWithHash)
	}

}
