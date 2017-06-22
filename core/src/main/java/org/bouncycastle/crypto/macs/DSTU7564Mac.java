package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.DSTU7564Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Pack;

/**
 * Implementation of DSTU7564 MAC mode
 */
public class DSTU7564Mac
    implements Mac
{
    private static final int BITS_IN_BYTE = 8;

    private DSTU7564Digest engine;

    private int macSize;

    private byte[] paddedKey;
    private byte[] invertedKey;

    private long inputLength;

    public DSTU7564Mac(int macBitSize)
    {
        /* Mac size can be only 256 / 384 / 512. Same as hash size for DSTU7654Digest */
        this.engine = new DSTU7564Digest(macBitSize);
        this.macSize = macBitSize / BITS_IN_BYTE;

        this.paddedKey = null;
        this.invertedKey = null;
    }

    public void init(CipherParameters params)
        throws IllegalArgumentException
    {
        if (params instanceof KeyParameter)
        {
            byte[] key = ((KeyParameter)params).getKey();

            invertedKey = new byte[key.length];

            paddedKey = padKey(key, 0, key.length);

            for (int byteIndex = 0; byteIndex < invertedKey.length; byteIndex++)
            {
                invertedKey[byteIndex] = (byte)(key[byteIndex] ^ (byte)0xFF);
            }
        }
        else
        {
            throw new IllegalArgumentException("Bad parameter passed");
        }

        engine.update(paddedKey, 0, paddedKey.length);
    }

    public String getAlgorithmName()
    {
        return "DSTU7564Mac";
    }

    public int getMacSize()
    {
        return macSize;
    }

    public void update(byte in)
        throws IllegalStateException
    {
        engine.update(in);
        inputLength++;
    }

    public void update(byte[] in, int inOff, int len)
        throws DataLengthException, IllegalStateException
    {
        if (in.length - inOff < len)
        {
            throw new DataLengthException("Input buffer too short");
        }

        if (paddedKey == null)
        {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        }

        engine.update(in, inOff, len);
        inputLength += len;
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (out.length - outOff < macSize)
        {
            throw new DataLengthException("Output buffer too short");
        }
        if (paddedKey == null)
        {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        }

        pad();

        engine.update(invertedKey, 0, invertedKey.length);
        
        inputLength = 0;

        return engine.doFinal(out, outOff);
    }

    public void reset()
    {
        inputLength = 0;
        engine.reset();
    }

    private void pad()
    {
        int extra = engine.getByteLength() - (int)(inputLength % engine.getByteLength());
        if (extra < 12)
        {
            extra = engine.getByteLength();
        }

        byte[] padded = new byte[extra];
           
        padded[0] = (byte)0x80; // Defined in standard;

        // Defined in standard;
        Pack.longToLittleEndian(inputLength * BITS_IN_BYTE, padded, padded.length - 12);

        engine.update(padded, 0, padded.length);
    }

    private byte[] padKey(byte[] in, int inOff, int len)
    {
        byte[] padded;
        if (len % engine.getByteLength() == 0)
        {
            padded = new byte[len + engine.getByteLength()];
        }
        else
        {
            int blocks = len / engine.getByteLength();
            padded = new byte[(blocks * engine.getByteLength()) + engine.getByteLength()];
        }

        System.arraycopy(in, inOff, padded, 0, len);
  
        padded[len] = (byte)0x80; // Defined in standard;
        Pack.intToLittleEndian(len * BITS_IN_BYTE, padded, padded.length - 12); // Defined in standard;

        return padded;
    }
}