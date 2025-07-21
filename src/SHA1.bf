namespace BeefCrypto;

using System;
using System.IO;
using System.Security.Cryptography;

struct SHA1Hash : IParseable<SHA1Hash>, IHashable
{
	public uint8[20] mHash;

	public static Result<SHA1Hash> Parse(StringView str)
	{
		if (str.Length != 64)
			return .Err;

		SHA1Hash hash = ?;

		Result<uint8> ParseChar(char8 c)
		{
			if ((c >= '0') && (c <= '9'))
				return (uint8)(c - '0');
			if ((c >= 'A') && (c <= 'F'))
				return (uint8)(c - 'A' + 10);
			if ((c >= 'a') && (c <= 'f'))
				return (uint8)(c - 'a' + 10);
			return .Err;
		}

		for (int i < 20)
		{
			hash.mHash[i] =
	            (Try!(ParseChar(str[i * 2 + 0])) << 4) |
				(Try!(ParseChar(str[i * 2 + 1])));
		}

		return hash;
	}

	public bool IsZero
	{
		get
		{
			for (int i < 20)
				if (mHash[i] != 0)
					return false;
			return true;
		}
	}
	
	public override void ToString(String strBuffer)
	{
		for (let val in mHash)
		{
			val.ToString(strBuffer, "X2", null);
		}
	}

	public void Encode(String outStr)
	{
#unwarn
		HashEncode.HashEncode64(((uint64*)&mHash)[0], outStr);
#unwarn
		HashEncode.HashEncode64(((uint64*)&mHash)[1], outStr);
#unwarn
		HashEncode.HashEncode64(((uint64*)&mHash)[2], outStr);
#unwarn
		HashEncode.HashEncode64(((uint64*)&mHash)[3], outStr);
	}

	public int GetHashCode()
	{
#unwarn
		return *(int*)&mHash;
	}
}

class SHA1
{
	uint32[5] mState;
	uint32[16] mData;
    uint64 byteCount;
    uint8 bufferOffset;

    const int SHA1_K0 = 0x5a827999;
    const int SHA1_K20 = 0x6ed9eba1;
    const int SHA1_K40 = 0x8f1bbcdc;
    const int SHA1_K60 = 0xca62c1d6;
    const int SHA1_BLOCK_LENGTH = 64;
    const int SHA1_DIGEST_LENGTH = 20;

	public this()
	{
		byteCount = 0;
		bufferOffset = 0;
		mState[0] = 0x67452301;
		mState[1] = 0xefcdab89;
		mState[2] = 0x98badcfe;
		mState[3] = 0x10325476;
		mState[4] = 0xc3d2e1f0;
		mData = .(?);
	}

    uint32 rol32(uint32 number, uint8 bits)
    {
    	return (number << bits) | (number >> (32 - bits));
    }

    void hashBlock()
    {
        uint8 i;
        uint32 a, b, c, d, e, t;

        a = mState[0];
        b = mState[1];
        c = mState[2];
        d = mState[3];
        e = mState[4];
        for (i = 0; i < 80; i++)
        {
            if (i >= 16)
            {
                t = mData[(i + 13) & 15] ^ mData[(i + 8) & 15] ^ mData[(i + 2) & 15] ^ mData[i & 15];
                mData[i & 15] = rol32(t, 1);
            }
            if (i < 20)
            {
                t = (d ^ (b & (c ^ d))) + SHA1_K0;
            }
            else if (i < 40)
            {
                t = (b ^ c ^ d) + SHA1_K20;
            }
            else if (i < 60)
            {
                t = ((b & c) | (d & (b | c))) + SHA1_K40;
            }
            else
            {
                t = (b ^ c ^ d) + SHA1_K60;
            }
            t += rol32(a, 5) + e + mData[i & 15];
            e = d;
            d = c;
            c = rol32(b, 30);
            b = a;
            a = t;
        }
        mState[0] += a;
        mState[1] += b;
        mState[2] += c;
        mState[3] += d;
        mState[4] += e;
    }

    void addUncounted(uint8 data)
    {
        uint8* b = (uint8*)&mData;
#if BF_BIG_ENDIAN
        b[bufferOffset] = data;
#else
        b[bufferOffset ^ 3] = data;
#endif
        bufferOffset++;
        if (bufferOffset == SHA1_BLOCK_LENGTH)
        {
            hashBlock();
            bufferOffset = 0;
        }
    }

	public void Update(Span<uint8> data)
	{
		for (int i = 0; i < data.Length; ++i)
		{
            byteCount++;
            addUncounted(data[i]);
		}
	}

	public SHA1Hash Finish()
	{
        // Pad with 0x80 followed by 0x00 until the end of the block
        addUncounted(0x80);
        while (bufferOffset != 56)
        {
            addUncounted(0x00);
        }

        // Append length in the last 8 bytes
        addUncounted((uint8)(byteCount >> 53)); // Shifting to multiply by 8
        addUncounted((uint8)(byteCount >> 45)); // as SHA-1 supports bitstreams
        addUncounted((uint8)(byteCount >> 37)); // as well as byte.
        addUncounted((uint8)(byteCount >> 29));
        addUncounted((uint8)(byteCount >> 21));
        addUncounted((uint8)(byteCount >> 13));
        addUncounted((uint8)(byteCount >> 5));
        addUncounted((uint8)(byteCount << 3));

#if BF_BIG_ENDIAN
        // Swap byte order back
        for (int i = 0; i < 5; i++)
        {
            mState[i] = (((mState[i]) << 24) & 0xff000000) | (((mState[i]) << 8) & 0x00ff0000) |
                        (((mState[i]) >> 8) & 0x0000ff00) | (((mState[i]) >> 24) & 0x000000ff);
        }
#endif

        SHA1Hash res = SHA1Hash();

        for (int ii = 0; ii < 4; ii++)
        {
            res.mHash[ii] = (.)(mState[0] >> (24 - ii * 8));
            res.mHash[ii + 4] = (.)(mState[1] >> (24 - ii * 8));
            res.mHash[ii + 8] = (.)(mState[2] >> (24 - ii * 8));
            res.mHash[ii + 12] = (.)(mState[3] >> (24 - ii * 8));
            res.mHash[ii + 16] = (.)(mState[4] >> (24 - ii * 8));
        }

        return res;
	}

	public static SHA1Hash Hash(Span<uint8> data)
	{
		let sha1 = scope SHA1();
		sha1.Update(data);
		return sha1.Finish();
	}
	
	public static Result<SHA1Hash> Hash(Stream stream)
	{
		let sha1 = scope SHA1();

		while (true)
		{
			uint8[4096] buffer;
			switch (stream.TryRead(.(&buffer, 4096)))
			{
			case .Ok(let bytes):
				if (bytes == 0)
                {
					return sha1.Finish();
                }
				sha1.Update(.(&buffer, bytes));
			case .Err(let err):
				return .Err(err);
			}
		}

		return sha1.Finish();
	}
}
