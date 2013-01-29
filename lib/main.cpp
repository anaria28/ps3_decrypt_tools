/*
* Copyright (c) 2011-2012 by ps3dev.net
* This file is released under the GPLv2.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "util.h"
#include "keys.h"
#include "eid.h"
#include "hdd.h"
#include "kgen.h"
#include "types.h"

void decrypt_hdd()
{
    u8 ata_k1[0x20], ata_k2[0x20], edec_k1[0x20], edec_k2[0x20];
	u32 size;

	//Fetching eid_root_key
	u8 *eid_root_key = _read_buffer("data/eid_root_key", NULL);
	//Assuming sectors start with sector 0.
	u8 *sectors = _read_buffer("data/sectors", &size);

	//Generate keys.
	generate_ata_keys(eid_root_key, eid_root_key + 0x20, ata_k1, ata_k2);
	generate_encdec_keys(eid_root_key, eid_root_key + 0x20, edec_k1, edec_k2);

	_hexdump(stdout, "ATA-DATA-KEY    ", 0, ata_k1, 0x20, 0);
	_hexdump(stdout, "ATA-TWEAK-KEY   ", 0, ata_k2, 0x20, 0);
	_hexdump(stdout, "ENCDEC-DATA-KEY ", 0, edec_k1, 0x20, 0);
	_hexdump(stdout, "ENCDEC-TWEAK-KEY", 0, edec_k2, 0x20, 0);

	//Decrypt all sectors.
	decrypt_sectors(sectors, 0, size, ata_k1, ata_k2, 1);
	//Decrypt VFLASH sectors starting at sector 8.
	decrypt_sectors(sectors+8*SECTOR_SIZE, 8, size - 8*SECTOR_SIZE, edec_k1, edec_k2, 0);

	_write_buffer("data/sectors_decrypted", sectors, size);

}

void decrypt_eid()
{
    //decrypting eEID
	eid_unpack("eid/eid");

	eid0_decrypt("eid/eid0","eid/eid0decrypted");
	eid1_decrypt("eid/eid1","eid/eid1decrypted");
	eid2_generate_block("eid/eid2",EID2_BLOCKTYPE_P,"eid/eid2pblock");
	eid2_generate_block("eid/eid2",EID2_BLOCKTYPE_S,"eid/eid2sblock");
	eid4_decrypt("eid/eid4","eid/eid4decrypted");
}

int main()
{
    int i;
    printf("Select an option\n1-Decrypt HDD\n2-Decrypt eEID(0,1,2,4 ONLY)\n3-Decrypt ALL\n0-Exit\n");
    scanf("%d",&i);
    switch(i)
    {
        case 1:
            decrypt_hdd();
            break;
        case 2:
            decrypt_eid();
            break;
        case 3:
            decrypt_hdd();
            decrypt_eid();
        case 0:
            break;
        default:
            printf("Incorrect Option Selected! Try Again.");
            break;
    }
    return 0;
}
