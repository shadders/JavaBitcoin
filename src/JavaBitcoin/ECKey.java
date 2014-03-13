/**
 * Copyright 2011 Google Inc.
 * Copyright 2013 Ronald W Hoffman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package JavaBitcoin;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x9.X9ECParameters;

import org.bouncycastle.crypto.ec.CustomNamedCurves;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Supports elliptic curve signature verification using a supplied public key.
 * It cannot be used to create signatures since we don't use a private key
 * on the network node.
 */
public class ECKey {

    /** Elliptic curve parameters for use with Bitcoin */
    private static final ECDomainParameters ecParams;
    static {
        X9ECParameters params = CustomNamedCurves.getByName("secp256k1");
        ecParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    }

    /** Public key */
    private byte[] pubKey;

    /**
     * Creates an ECKey with just a public key
     *
     * @param       pubKey              Public key
     */
    public ECKey(byte[] pubKey) {
        this.pubKey = pubKey;
    }

    /**
     * Checks if the public key is canonical
     *
     * @param       pubKeyBytes         Public key
     * @return                          TRUE if the key is canonical
     */
    public static boolean isPubKeyCanonical(byte[] pubKeyBytes) {
        boolean isValid = false;
        if (pubKeyBytes.length == 33 && (pubKeyBytes[0] == (byte)0x02 || pubKeyBytes[0] == (byte)0x03)) {
            isValid = true;
        } else if (pubKeyBytes.length == 65 && pubKeyBytes[0] == (byte)0x04) {
            isValid = true;
        }
        return isValid;
    }

    /**
     * Checks if the signature is DER-encoded
     *
     * @param       encodedSig          Encoded signature
     * @return                          TRUE if the signature is DER-encoded
     */
    public static boolean isSignatureCanonical(byte[] encodedSig) {
        //
        // DER-encoding requires that there is only one representation for a given
        // encoding.  This means that no pad bytes are inserted for numeric values.
        //
        // An ASN.1 sequence is identified by 0x30 and each primitive by a type field.
        // An integer is identified as 0x02.  Each field type is followed by a field length.
        // For valid R and S values, the length is a single byte since R and S are both
        // 32-byte or 33-byte values (a leading zero byte is added to ensure a positive
        // value if the sign bit would otherwise bet set).
        //
        // Bitcoin appends that hash type to the end of the DER-encoded signature.  We require
        // this to be a single byte for a canonical signature.
        //
        // The length is encoded in the lower 7 bits for lengths between 0 and 127 and the upper bit is 0.
        // Longer length have the upper bit set to 1 and the lower 7 bits contain the number of bytes
        // in the length.
        //

        //
        // An ASN.1 sequence is 0x30 followed by the length
        //
        if (encodedSig.length < 2 || encodedSig[0] != (byte)0x30 || (encodedSig[1]&0x80) != 0)
            return false;
        //
        // Get length of sequence
        //
        int length = ((int)encodedSig[1]&0x7f) + 2;
        int offset = 2;
        //
        // Check R
        //
        if (offset+2 > length || encodedSig[offset] != (byte)0x02 || (encodedSig[offset+1]&0x80) != 0)
            return false;
        int rLength = (int)encodedSig[offset+1]&0x7f;
        if (offset+rLength+2 > length)
            return false;
        if (encodedSig[offset+2] == 0x00 && (encodedSig[offset+3]&0x80) == 0)
            return false;
        offset += rLength + 2;
        //
        // Check S
        //
        if (offset+2 > length || encodedSig[offset] != (byte)0x02 || (encodedSig[offset+1]&0x80) != 0)
            return false;
        int sLength = (int)encodedSig[offset+1]&0x7f;
        if (offset+sLength+2 > length)
            return false;
        if (encodedSig[offset+2] == 0x00 && (encodedSig[offset+3]&0x80) == 0)
            return false;
        offset += sLength + 2;
        //
        // There must be a single byte appended to the signature
        //
        return (offset == encodedSig.length-1);
    }

    /**
     * Verifies a signature
     *
     * @param       contents            The signed contents or null to use error hash
     * @param       signature           DER-encoded signature
     * @return      TRUE if the signature if valid, FALSE otherwise
     * @throws      ECException         Unable to verify the signature
     */
    public boolean verifySignature(byte[] contents, byte[] signature) throws ECException {
        boolean isValid = false;
        //
        // Decode the DER-encoded signature and get the R and S values
        //
        BigInteger r;
        BigInteger s;
        try {
            try (ASN1InputStream decoder = new ASN1InputStream(signature)) {
                DLSequence seq = (DLSequence)decoder.readObject();
                r = ((ASN1Integer)seq.getObjectAt(0)).getPositiveValue();
                s = ((ASN1Integer)seq.getObjectAt(1)).getPositiveValue();
            }
        } catch (IOException | ClassCastException exc) {
            throw new ECException("ASN.1 failure while decoding signature", exc);
        }
        //
        // Get the double SHA-256 hash of the signed contents
        //
        // A null contents will result in a hash with the first byte set to 1 and
        // all other bytes set to 0.  This is needed to handle a bug in the reference
        // client where it doesn't check for an error when serializing a transaction
        // and instead uses the error code as the hash.
        //
        byte[] contentsHash;
        if (contents != null) {
            contentsHash = Utils.doubleDigest(contents);
        } else {
            contentsHash = new byte[32];
            contentsHash[0] = 0x01;
        }
        //
        // Verify the signature
        //
        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters params;
        try {
            params = new ECPublicKeyParameters(ecParams.getCurve().decodePoint(pubKey), ecParams);
            signer.init(false, params);
            isValid = signer.verifySignature(contentsHash, r, s);
        } catch (RuntimeException exc) {
            throw new ECException("Runtime exception while verifying signature", exc);
        }
        return isValid;
    }
}
