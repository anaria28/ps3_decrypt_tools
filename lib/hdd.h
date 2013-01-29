#ifndef _HDD_H_
#define _HDD_H_

void _es16_buffer(u8 *buf, u32 length);
int decrypt_sectors(u8 *sectors, u64 sec_start, u32 size, u8 *k1, u8 *k2, int endian_swap_16);

#endif
