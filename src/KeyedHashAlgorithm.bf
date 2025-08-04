namespace BeefCrypto;

// ==++==
// 
//   Copyright (c) Microsoft Corporation.  All rights reserved.
// 
// ==--==
// <OWNER>Microsoft</OWNER>
// 

//
// KeyedHashAlgorithm.cs
//

public abstract class KeyedHashAlgorithm : HashAlgorithm {
    protected uint8[] KeyValue;

    protected this() {}

    // IDisposable methods
    protected override void Dispose(bool disposing) {
        // For keyed hash algorithms, we always want to zero out the key value
        if (disposing) {
            if (KeyValue != null)
                KeyValue.SetAll(0);
            KeyValue = null;
        }
        base.Dispose(disposing);
    }

    //
    // public properties
    //

    public virtual uint8[] Key {
        get {
            uint8[] thekey = new uint8[KeyValue.Count];
            KeyValue.CopyTo(thekey);
            return KeyValue;
        }
        set {
            if (State == 0)
                value.CopyTo(KeyValue);
        }
    }

    //
    // public methods
    //

    /*new static public KeyedHashAlgorithm Create() {
        return Create("System.Security.Cryptography.KeyedHashAlgorithm");
    }

    new static public KeyedHashAlgorithm Create(String algName) {
        return (KeyedHashAlgorithm) CryptoConfig.CreateFromName(algName);    
    }*/
}
