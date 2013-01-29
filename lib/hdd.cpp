#include "kgen.h"
#include "aes_xts.h"
#include "types.h"

/*! Swap u16 endianness. */
void _es16_buffer(u8 *buf, u32 length)
{
	u16 *ptr = (u16 *)buf;
	u32 i;

	for(i = 0; i < length/2; i++)
		ptr[i] = _ES16(ptr[i]);
}

/*! Decrypt sectors. */
int decrypt_sectors(u8 *sectors, u64 sec_start, u32 size, u8 *k1, u8 *k2, int endian_swap_16)
{
	u32 i;
	aes_xts_ctxt_t xts_ctxt;

	//Check if size is a multiple of sector size.
	if(!(size % SECTOR_SIZE == 0))
		return -1;

	//Swap endianness if wanted.
	if(endian_swap_16)
		_es16_buffer(sectors, size);

	//Init AES-XTS context.
	aes_xts_init(&xts_ctxt, AES_DECRYPT, k1, k2, 128);

	//Decrypt sectors.
	for(i = 0; i < size; i += SECTOR_SIZE)
		aes_xts_crypt(&xts_ctxt, sec_start + i / SECTOR_SIZE, SECTOR_SIZE, sectors + i, sectors + i);

	return 0;
}
