namespace BeefCrypto;

// ==++==
// 
//   Copyright (c) Microsoft Corporation.  All rights reserved.
// 
// ==--==
// <OWNER>Microsoft</OWNER>
// 

//
// HashAlgorithm.cs
//
using System;
using System.IO;

enum HashError
{
    case ObjectDisposedException;
    case CryptographicUnexpectedOperationException(StringView err);
    case ArgumentNullException(StringView err);
    case ArgumentOutOfRangeException(StringView err, StringView msg);
    case ArgumentException(StringView err);
    case PlatformNotSupportedException(StringView err, StringView msg);
    case InvalidOperationException(StringView err, StringView msg);

}

public abstract class HashAlgorithm : IDisposable
{
    protected int HashSizeValue;
    protected internal uint8[] HashValue;
    protected int State = 0;

    private bool m_bDisposed = false;

    protected this() {}

    //
    // public properties
    //

    public virtual int HashSize {
        get { return HashSizeValue; }
    }

    public virtual Result<uint8[], HashError> Hash {
        get {
            if (m_bDisposed) 
                return .Err(.ObjectDisposedException);
            if (State != 0)
                return .Err(.CryptographicUnexpectedOperationException(Environment.[Friend]GetResourceString("Cryptography_HashNotYetFinalized")));
            uint8[] ouVal = new uint8[HashValue.Count];
            HashValue.CopyTo(ouVal);
            return ouVal;
        }
    }

    //
    // public methods
    //

    /*static public HashAlgorithm Create() {
        return Create("System.Security.Cryptography.HashAlgorithm");
    }

    static public HashAlgorithm Create(String hashName) {
        return (HashAlgorithm) CryptoConfig.CreateFromName(hashName);
    }*/

    public Result<uint8[], HashError> ComputeHash(Stream inputStream) {
        if (m_bDisposed) 
            return .Err(.ObjectDisposedException);

        // Default the buffer size to 4K.
        uint8[] buffer = scope uint8[4096];
        int bytesRead = 1;
        repeat {
            if (inputStream.TryRead(buffer) case .Ok(out bytesRead)) {
                if (bytesRead > 0) {
                    HashCore(buffer, 0, bytesRead);
                }
            }
        } while (bytesRead > 0);

        HashValue = HashFinal();
        uint8[] Tmp = new uint8[HashValue.Count];
        HashValue.CopyTo(Tmp);

        Initialize();
        return Tmp;
    }

    public Result<uint8[], HashError> ComputeHash(uint8[] buffer) {
        if (m_bDisposed) 
            return .Err(.ObjectDisposedException);

        // Do some validation
        if (buffer == null)
            return .Err(.ArgumentNullException("buffer"));

        HashCore(buffer, 0, buffer.Count);
        HashValue = HashFinal();
        uint8[] Tmp = new uint8[HashValue.Count];
        HashValue.CopyTo(Tmp);
        Initialize();
        return Tmp;
    }

    public Result<uint8[], HashError> ComputeHash(uint8[] buffer, int offset, int count) {
        // Do some validation
        if (buffer == null)
            return .Err(.ArgumentNullException("buffer"));
        if (offset < 0)
            return .Err(.ArgumentOutOfRangeException("offset", Environment.[Friend]GetResourceString("ArgumentOutOfRange_NeedNonNegNum")));
        if (count < 0 || (count > buffer.Count))
            return .Err(.ArgumentException(Environment.[Friend]GetResourceString("Argument_InvalidValue")));
        if ((buffer.Count - count) < offset)
            return .Err(.ArgumentException(Environment.[Friend]GetResourceString("Argument_InvalidOffLen")));
        //Contract.EndContractBlock();

        if (m_bDisposed)
            return .Err(.ObjectDisposedException);

        HashCore(buffer, offset, count);
        HashValue = HashFinal();
        uint8[] Tmp = new uint8[HashValue.Count];
        HashValue.CopyTo(Tmp);
        Initialize();
        return Tmp;
    }

    // ICryptoTransform methods

    // we assume any HashAlgorithm can take input a byte at a time
    public virtual int InputBlockSize { 
        get { return(1); }
    }

    public virtual int OutputBlockSize {
        get { return(1); }
    }

    public virtual bool CanTransformMultipleBlocks { 
        get { return(true); }
    }

    public virtual bool CanReuseTransform { 
        get { return(true); }
    }

    // We implement TransformBlock and TransformFinalBlock here
    public Result<int, HashError> TransformBlock(uint8[] inputBuffer, int inputOffset, int inputCount, uint8[] outputBuffer, int outputOffset) {
        // Do some validation, we let BlockCopy do the destination array validation
        if (inputBuffer == null)
            return .Err(.ArgumentNullException("inputBuffer"));
        if (inputOffset < 0)
            return .Err(.ArgumentOutOfRangeException("inputOffset", Environment.[Friend]GetResourceString("ArgumentOutOfRange_NeedNonNegNum")));
        if (inputCount < 0 || (inputCount > inputBuffer.Count))
            return .Err(.ArgumentException(Environment.[Friend]GetResourceString("Argument_InvalidValue")));
        if ((inputBuffer.Count - inputCount) < inputOffset)
            return .Err(.ArgumentException(Environment.[Friend]GetResourceString("Argument_InvalidOffLen")));
        //Contract.EndContractBlock();

        if (m_bDisposed)
            return .Err(.ObjectDisposedException);

        // Change the State value
        State = 1;
        HashCore(inputBuffer, inputOffset, inputCount);
        if ((outputBuffer != null) && ((inputBuffer != outputBuffer) || (inputOffset != outputOffset)))
            inputBuffer.CopyTo(outputBuffer, inputOffset, outputOffset, inputCount);
        return inputCount;
    }

    public Result<uint8[], HashError> TransformFinalBlock(uint8[] inputBuffer, int inputOffset, int inputCount) {
        // Do some validation
        if (inputBuffer == null)
            return .Err(.ArgumentNullException("inputBuffer"));
        if (inputOffset < 0)
            return .Err(.ArgumentOutOfRangeException("inputOffset", Environment.[Friend]GetResourceString("ArgumentOutOfRange_NeedNonNegNum")));
        if (inputCount < 0 || (inputCount > inputBuffer.Count))
            return .Err(.ArgumentException(Environment.[Friend]GetResourceString("Argument_InvalidValue")));
        if ((inputBuffer.Count - inputCount) < inputOffset)
            return .Err(.ArgumentException(Environment.[Friend]GetResourceString("Argument_InvalidOffLen")));
        //Contract.EndContractBlock();

        if (m_bDisposed)
            return .Err(.ObjectDisposedException);

        HashCore(inputBuffer, inputOffset, inputCount);
        HashValue = HashFinal();
        uint8[] outputBytes = new uint8[inputCount];
        if (inputCount != 0)
        {
            inputBuffer.CopyTo(outputBytes, inputOffset, 0, inputCount);
        }
        // reset the State value
        State = 0;
        return outputBytes;
    }

    // IDisposable methods

    // To keep mscorlib compatibility with Orcas, CoreCLR's HashAlgorithm has an explicit IDisposable
    // implementation. Post-Orcas the desktop has an implicit IDispoable implementation.
#if FEATURE_CORECLR
    void IDisposable.Dispose()
    {
        Dispose();
    }
#endif // FEATURE_CORECLR

    public void Dispose()
    {
        Dispose(true);
        //GC.SuppressFinalize(this);
    }

    public void Clear() {
        Dispose();
    }

    protected virtual void Dispose(bool disposing) {
        if (disposing) {
            if (HashValue != null)
                Array.Clear(HashValue, 0, HashValue.Count);
            HashValue = null;
            m_bDisposed = true;
        }
    }

    //
    // abstract public methods
    //

    public abstract void Initialize();

    protected abstract void HashCore(uint8[] array, int ibStart, int cbSize);

    protected abstract uint8[] HashFinal();
}
