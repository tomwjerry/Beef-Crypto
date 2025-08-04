namespace BeefCrypto;

using System;

public class HMACSHA1 : HMAC
{
    //
    // public constructors
    //

    //public this() : this (Utils.GenerateRandom(64)) {}

    public this(Span<uint8> key) : this (key, false) {}

    public this(Span<uint8> key, bool useManagedSha1)
    {
        m_hashName = "SHA1";
        m_hash1 = new SHA1();
        m_hash2 = new SHA1();

        HashSizeValue = 160;
        uint8[] keyarr = new uint8[key.Length];
        key.CopyTo(keyarr);
        base.InitializeKey(keyarr);
    }

    public ~this()
    {
        delete m_hash1;
        delete m_hash2;
    }
}
