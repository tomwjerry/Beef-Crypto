namespace BeefCrypto;

using System;

/**
 * The code is based on the following contributions:
 *
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

class CRC
{
    const int CRC32_REVERSED_POLY = 0xEDB88320;
    const int CRC32_INIT = 0xFFFFFFFF;
    const int CRC32_XOR = 0xFFFFFFFF;
    private static uint32[256] table = uint32[256](0,);

    private static uint32 crc32_byte(uint32 crc)
    {
        uint32 newcrc = crc;
    	for (int i = 0; i < 8; ++i)
        {
    		if (newcrc & 1 == 1)
            {
    			newcrc = (newcrc >> 1) ^ CRC32_REVERSED_POLY;
            }
    		else
            {    
    			newcrc = (newcrc >> 1);
            }
        }
    	return newcrc;
    }

    public static uint32 Hash(Span<uint8> data)
    {
        if (table[255] == 0)
        {
            for (uint32 i = 0; i < 256; ++i)
            {
	            table[i] = crc32_byte(i);
            }
        }
    	
        uint32 crc = CRC32_INIT;
        for (uint8 p in data)
        {
        	crc = table[(uint8)(crc & 0xFF) ^ p] ^ (crc >> 8);
        }
        return crc ^ CRC32_XOR;
    }
}
