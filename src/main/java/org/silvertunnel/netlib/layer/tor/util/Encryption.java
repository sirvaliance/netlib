/*
 * OnionCoffee - Anonymous Communication through TOR Network
 * Copyright (C) 2005-2007 RWTH Aachen University, Informatik IV
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */
/*
 * silvertunnel.org Netlib - Java library to easily access anonymity networks
 * Copyright (c) 2009-2012 silvertunnel.org
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */
package org.silvertunnel.netlib.layer.tor.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.JCERSAPrivateCrtKey;
import org.bouncycastle.jce.provider.JCERSAPrivateKey;
import org.bouncycastle.jce.provider.JCERSAPublicKey;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.encoders.Base64;



/**
 * this class contains utility functions concerning encryption
 * 
 * @author Lexi Pimenidis
 * @author Andriy Panchenko
 * @author Michael Koellejan
 * @author hapke
 */
public class Encryption {
    private static final Logger log = Logger.getLogger(Encryption.class.getName());

    public static final String DIGEST_ALGORITHM = "SHA-1";
    private static final String PK_ALGORITHM = "RSA";

    static {
        try {
            // install BC, if not already done
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                // Security.insertProviderAt(new
                // org.bouncycastle.jce.provider.BouncyCastleProvider(),2);
            }
        } catch (Throwable t) {
            log.log(Level.SEVERE, "Cannot initialize class Encryption", t);
        }
    }
    
    /**
     * returns the SHA-1 of the input
     * 
     * @param input
     * @return digest value
     */
    public static byte[] getDigest(byte[] input) {
        return getDigest(DIGEST_ALGORITHM, input);
    }
    /**
     * returns the digest of the input
     * 
     * @param algorithm    e.g. "SHA-1"
     * @param input
     * @return digest value
     */
    public static byte[] getDigest(String algorithm, byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            md.reset();
            md.update(input, 0, input.length);
            return md.digest();

        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * @return implementation of the SHA-1 message digest; reset() already called
     */
    public static MessageDigest getMessagesDigest() {
        try {
            MessageDigest md = MessageDigest.getInstance(DIGEST_ALGORITHM);
            md.reset();
            return md;

        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Calculate the digest but do not touch md.
     * 
     * @param md
     * @return the digest, calculated with a clone of md
     */
    public static byte[] intermediateDigest(MessageDigest md) {
        try {
            // ugly fix around the behavior on digests
            MessageDigest mdClone = (MessageDigest)md.clone();
            return mdClone.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    /**
     * checks signature of PKCS1-padded SHA1 hash of the input
     * 
     * Hint: A different implementation of this method can be found in the svn history revision<=229. 
     * 
     * @param signature
     *            signature to check
     * @param signingKey
     *            public key from signing
     * @param input
     *            byte array, signature is made over
     * 
     * @return true, if the signature is correct
     * 
     */
    public static boolean verifySignature(byte[] signature, RSAPublicKeyStructure signingKey, byte[] input) {
        byte[] hash = getDigest(input);
    
        try {
            RSAKeyParameters myRSAKeyParameters = new RSAKeyParameters(false,
                    signingKey.getModulus(), signingKey.getPublicExponent());
    
            PKCS1Encoding pkcsAlg = new PKCS1Encoding(new RSAEngine());
            pkcsAlg.init(false, myRSAKeyParameters);
    
            byte[] decryptedSignature = pkcsAlg.processBlock(signature, 0, signature.length);
    
            return Encoding.arraysEqual(hash, decryptedSignature);
    
        } catch (Exception e) {
            log.log(Level.WARNING, "unexpected", e);
            return false;
        }
    }
    /**
     * checks row signature
     * 
     * @param signature
     *            signature to check
     * @param signingKey
     *            public key from signing
     * @param input
     *            byte array, signature is made over
     * 
     * @return true, if the signature is correct
     * 
     */
    public static boolean verifySignatureXXXX(byte[] signature,
            RSAPublicKeyStructure signingKey, byte[] input) {
    
        byte[] hash = getDigest(input);
        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(signingKey
                    .getModulus(), signingKey.getPublicExponent());
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
            sig.initVerify(pubKey);
            sig.update(input);
            log.info("");
            log.info(" HERE -> " + sig.verify(signature));
    
            RSAKeyParameters myRSAKeyParameters = new RSAKeyParameters(false,
                    signingKey.getModulus(), signingKey.getPublicExponent());
            RSAEngine rsaAlg = new RSAEngine();
            rsaAlg.init(false, myRSAKeyParameters);
            byte[] decryptedSignature = rsaAlg.processBlock(signature, 0, signature.length);
            log.info(" inpu = " + Encoding.toHexString(input));
            log.info(" hash = " + Encoding.toHexString(hash));
            log.info("");
            log.info(" sign = " + Encoding.toHexString(signature));
            log.info(" decr = " + Encoding.toHexString(decryptedSignature));
    
            return Encoding.arraysEqual(hash, decryptedSignature);
    
        } catch (Exception e) {
            log.log(Level.WARNING, "unexpected", e);
            return false;
        }
    }

    public static boolean verifySignature(byte[] signature, PublicKey signingKey, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance(PK_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, signingKey);
            byte[] decryptedDigest = cipher.doFinal(signature);
            byte[] dataDigest = getDigest(DIGEST_ALGORITHM, data);
            if (decryptedDigest!=null && dataDigest!=null && decryptedDigest.length>dataDigest.length) {
                // try to fix bug in security calculation with OpenJDK-6 java web start (ticket #59)
                log.warning("verifySignature(): try to fix bug in security calculation with OpenJDK-6 java web start (ticket #59)");
                log.warning("verifySignature(): original decryptedDigest="+Encoding.toHexString(decryptedDigest));
                log.warning("verifySignature(): dataDigest              ="+Encoding.toHexString(dataDigest));
                byte[] fixedDecryptedDigest = new byte[dataDigest.length];
                System.arraycopy(decryptedDigest, decryptedDigest.length-dataDigest.length, fixedDecryptedDigest, 0, dataDigest.length);
                decryptedDigest = fixedDecryptedDigest;
            }
            
            boolean verificationSuccessful = Arrays.equals(decryptedDigest, dataDigest);
            if (verificationSuccessful==false) {
                log.info("verifySignature(): decryptedDigest="+Encoding.toHexString(decryptedDigest));
                log.info("verifySignature(): dataDigest     ="+Encoding.toHexString(dataDigest));
            }
            
            return verificationSuccessful;
            
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * sign some data using a private key and PKCS#1 v1.5 padding
     * 
     * @param data
     *            the data to be signed
     * @param signingKey
     *            the key to sign the data
     * @return a signature
     */
    public static byte[] signData(byte[] data, RSAKeyParameters signingKey) {
        try {
            byte[] hash = Encryption.getDigest(data);
            PKCS1Encoding pkcs1 = new PKCS1Encoding(new RSAEngine());
            pkcs1.init(true, signingKey);
            return pkcs1.processBlock(hash, 0, hash.length);
        } catch (InvalidCipherTextException e) {
            log.log(Level.WARNING, "Common.signData(): " + e.getMessage(), e);
            return null;
        }
    }
    /**
     * sign some data using a private kjey and PKCS#1 v1.5 padding
     * 
     * @param data
     *            the data to be signed
     * @param signingKey
     *            the key to sign the data
     * @return a signature
     */
    public static byte[] signData(byte[] data, PrivateKey signingKey) {
        try {
            Cipher cipher = Cipher.getInstance(PK_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, signingKey);
            return cipher.doFinal(getDigest(DIGEST_ALGORITHM, data));

        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /** used to encode a signature in PEM */
    public static String binarySignatureToPEM(byte[] signature) {
        String sigB64 = Encoding.toBase64(signature);
        StringBuffer sig = new StringBuffer();
    
        sig.append("-----BEGIN SIGNATURE-----\n");
        while (sigB64.length() > 64) {
            sig.append(sigB64.substring(0, 64) + "\n");
            sigB64 = sigB64.substring(64);
        }
        sig.append(sigB64 + "\n");
        sig.append("-----END SIGNATURE-----\n");
        return sig.toString();
    }

    /**
     * makes RSA public key from PEM string
     * 
     * @param s    PEM string that contains the key
     * @return
     * @see JCERSAPublicKey
     */
    public static RSAPublicKey extractPublicRSAKey(String s) {
        RSAPublicKey theKey;
        try {
            PEMReader reader = new PEMReader(new StringReader(s));
            Object o = reader.readObject();
            if (!(o instanceof JCERSAPublicKey)) {
                throw new IOException("Encryption.extractPublicRSAKey: no public key found in string '" + s + "'");
            }
            JCERSAPublicKey JCEKey = (JCERSAPublicKey) o;
            theKey = getRSAPublicKey(JCEKey.getModulus(), JCEKey.getPublicExponent());
   
        } catch (Exception e) {
            log.warning("Encryption.extractPublicRSAKey: Caught exception:" + e.getMessage());
            theKey = null;
        }
    
        return theKey;
    }

    /**
     * makes RSA private key from PEM string
     * 
     * @param s    PEM string that contains the key
     * @return
     * @see JCERSAPublicKey
     */
    public static RSAKeyPair extractRSAKeyPair(String s) {
        RSAKeyPair rsaKeyPair;
        try {
            // parse
            PEMReader reader = new PEMReader(new StringReader(s));
            Object o = reader.readObject();
            
            // check types
            if (!(o instanceof KeyPair)) {
                throw new IOException("Encryption.extractRSAKeyPair: no private key found in string '" + s + "'");
            }
            KeyPair keyPair = (KeyPair)o;
            if (!(keyPair.getPrivate() instanceof JCERSAPrivateKey)) {
                throw new IOException("Encryption.extractRSAKeyPair: no private key found in key pair of string '" + s + "'");
            }
            if (!(keyPair.getPublic() instanceof JCERSAPublicKey)) {
                throw new IOException("Encryption.extractRSAKeyPair: no public key found in key pair of string '" + s + "'");
            }
            
            // convert keys and pack them together into a key pair
            RSAPrivateCrtKey privateKey = (JCERSAPrivateCrtKey)keyPair.getPrivate();
            log.finer("JCEPrivateKey="+privateKey);
            RSAPublicKey publicKey = (JCERSAPublicKey)keyPair.getPublic();
            rsaKeyPair = new RSAKeyPair(publicKey, privateKey);
            
        } catch (Exception e) {
            log.warning("Encryption.extractPrivateRSAKey: Caught exception:" + e.getMessage());
            rsaKeyPair = null;
        }
    
        return rsaKeyPair;
    }

    /**
     * Converts RSA private key to PEM string.
     * 
     * @param rsaKeyPair
     * 
     * @return PEM string
     */
    public static String getPEMStringFromRSAKeyPair(RSAKeyPair rsaKeyPair) {
        StringWriter pemStrWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(pemStrWriter);
        try {
            KeyPair keyPair = new KeyPair(rsaKeyPair.getPublic(), rsaKeyPair.getPrivate());
            //pemWriter.writeObject(keyPair);
            pemWriter.writeObject(keyPair.getPrivate());
            //pemWriter.flush();
            pemWriter.close();

        } catch (IOException e) {
            log.warning("Caught exception:" + e.getMessage());
            return "";
        }

        return pemStrWriter.toString();
    }
    

    /**
     * Create a key based on the parameters.
     * 
     * @param modulus
     * @param publicExponent
     * @return the key
     */
    public static RSAPublicKey getRSAPublicKey(BigInteger modulus, BigInteger publicExponent) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Create a key based on the parameters.
     * 
     * @param modulus
     * @param publicExponent
     * @return the key
     */
    public static RSAPrivateKey getRSAPrivateKey(BigInteger modulus, BigInteger privateExponent) {
        try {
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(modulus, privateExponent));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * makes RSA public key from bin byte array
     * 
     * @param s
     *            string that contais the key
     * @return
     * @see JCERSAPublicKey
     */
    public static RSAPublicKey extractBinaryRSAKey(byte[] b) {
        RSAPublicKey theKey;
    
        try {
            ASN1InputStream ais = new ASN1InputStream(b);
            Object asnObject = ais.readObject();
            ASN1Sequence sequence = (ASN1Sequence) asnObject;
            RSAPublicKeyStructure tempKey = new RSAPublicKeyStructure(sequence);
            theKey =  getRSAPublicKey(tempKey.getModulus(), tempKey.getPublicExponent());
            
        } catch (IOException e) {
            log.warning("Caught exception:" + e.getMessage());
            theKey = null;
        }
    
        return theKey;
    }

    /**
     * copy from one format to another
     */
    public static RSAPublicKey getRSAPublicKey(JCERSAPublicKey jpub) {
        return getRSAPublicKey(jpub.getModulus(), jpub.getPublicExponent());
    }

    /**
     * converts a RSAPublicKey into PKCS1-encoding (ASN.1)
     * 
     * @param rsaPublicKey
     * @see JCERSAPublicKey
     * @return PKCS1-encoded RSA PUBLIC KEY
     */
    public static byte[] getPKCS1EncodingFromRSAPublicKey(RSAPublicKey pubKeyStruct) {
        try {
            RSAPublicKeyStructure myKey = new RSAPublicKeyStructure(pubKeyStruct.getModulus(), pubKeyStruct.getPublicExponent());
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ASN1OutputStream aOut = new ASN1OutputStream(bOut);
            aOut.writeObject(myKey.toASN1Object());
            return bOut.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * converts a JCERSAPublicKey into PEM/PKCS1-encoding
     * 
     * @param rsaPublicKey
     * @see RSAPublicKeyStructure
     * @return PEM-encoded RSA PUBLIC KEY
     */
    public static String getPEMStringFromRSAPublicKey(RSAPublicKey rsaPublicKey) {
    
        // mrk: this was awful to program. Remeber: There are two entirely
        // different
        // standard formats for rsa public keys. Bouncy castle does only support
        // the
        // one we can't use for TOR directories.
    
        StringBuffer tmpDirSigningKey = new StringBuffer();
    
        try {
    
            tmpDirSigningKey.append("-----BEGIN RSA PUBLIC KEY-----\n");
    
            byte[] base64Encoding = Base64
                    .encode(getPKCS1EncodingFromRSAPublicKey(rsaPublicKey));
            for (int i = 0; i < base64Encoding.length; i++) {
                tmpDirSigningKey.append((char) base64Encoding[i]);
                if (((i + 1) % 64) == 0)
                    tmpDirSigningKey.append("\n");
            }
            tmpDirSigningKey.append("\n");
    
            tmpDirSigningKey.append("-----END RSA PUBLIC KEY-----\n");
        } catch (Exception e) {
            return null;
        }
    
        return tmpDirSigningKey.toString();
    }

    /**
     * encrypt data with asymmetric key. create asymmetricla encrypted data:<br>
     * <ul>
     * <li>OAEP padding [42 bytes] (RSA-encrypted)
     * <li>Symmetric key [16 bytes]                   FIXME: we assume that we ALWAYS need this 
     * <li>First part of data [70 bytes]
     * <li>Second part of data [x-70 bytes] (Symmetrically encrypted)
     * <ul>
     * encrypt and store in result
     * 
     * @param pub
     * @param symmetricKey    AES key  
     * @param data
     *            to be encrypted, needs currently to be at least 70 bytes long
     * @return the first half of the key exchange, ready to be send to the other
     *         partner
     */
    public static byte[] asymEncrypt(RSAPublicKey pub, byte[] symmetricKey, byte[] data) throws TorException {
        if (data == null) {
            throw new NullPointerException("can't encrypt NULL data");
        }
        if (data.length < 70) {
            throw new TorException("input array too short");
        }

        try {
            int encryptedBytes = 0;

            // initialize OAEP
            OAEPEncoding oaep = new OAEPEncoding(new RSAEngine());
            oaep.init(true, new RSAKeyParameters(false, pub.getModulus(), pub.getPublicExponent()));
            // apply RSA+OAEP
            encryptedBytes = oaep.getInputBlockSize();
            byte[] oaepInput = new byte[encryptedBytes];
            System.arraycopy(data, 0, oaepInput, 0, encryptedBytes);
            byte[] part1 = oaep.encodeBlock(oaepInput, 0, encryptedBytes);

            // initialize AES
            AESCounterMode aes = new AESCounterMode(true, symmetricKey);
            // apply AES
            byte[] aesInput = new byte[data.length - encryptedBytes];
            System.arraycopy(data, encryptedBytes, aesInput, 0, aesInput.length);
            byte part2[] = aes.processStream(aesInput);

            // replace unencrypted data
            byte[] result = new byte[part1.length + part2.length];
            System.arraycopy(part1, 0, result, 0, part1.length);
            System.arraycopy(part2, 0, result, part1.length, part2.length);

            return result;
        } catch (InvalidCipherTextException e) {
            log.severe("Node.asymEncrypt(): can't encrypt cipher text:" + e.getMessage());
            throw new TorException("InvalidCipherTextException:" + e.getMessage());
        }
    }
    /**
     * decrypt data with asymmetric key. create asymmetrically encrypted data:<br>
     * <ul>
     * <li>OAEP padding [42 bytes] (RSA-encrypted)
     * <li>Symmetric key [16 bytes]
     * <li>First part of data [70 bytes]
     * <li>Second part of data [x-70 bytes] (Symmetrically encrypted)
     * <ul>
     * encrypt and store in result
     * 
     * @param priv
     *            key to use for decryption
     * @param data
     *            to be decrypted, needs currently to be at least 70 bytes long
     * @return raw data
     */
    public static byte[] asymDecrypt(RSAPrivateKey priv, byte[] data)
            throws TorException {
    
        if (data == null) {
            throw new NullPointerException("can't encrypt NULL data");
        }
        if (data.length < 70) {
            throw new TorException("input array too short");
        }

        try {
            int encryptedBytes = 0;
    
            // init OAEP
            OAEPEncoding oaep = new OAEPEncoding(new RSAEngine());
            oaep.init(false, new RSAKeyParameters(true, priv.getModulus(), priv.getPrivateExponent()));
            // apply RSA+OAEP
            encryptedBytes = oaep.getInputBlockSize();
            byte[] oaepInput = new byte[encryptedBytes];
            System.arraycopy(data, 0, oaepInput, 0, encryptedBytes);
            byte[] part1 = oaep.decodeBlock(oaepInput, 0, encryptedBytes);
    
            // extract symmetric key
            byte[] symmetricKey = new byte[16];
            System.arraycopy(part1, 0, symmetricKey, 0, 16);
            // init AES
            AESCounterMode aes = new AESCounterMode(true, symmetricKey);
            // apply AES
            byte[] aesInput = new byte[data.length - encryptedBytes];
            System.arraycopy(data, encryptedBytes, aesInput, 0, aesInput.length);
            byte part2[] = aes.processStream(aesInput);
    
            // replace unencrypted data
            byte[] result = new byte[part1.length - 16 + part2.length];
            System.arraycopy(part1, 16, result, 0, part1.length - 16);
            System.arraycopy(part2, 0, result, part1.length - 16, part2.length);

            return result;
    
        } catch (InvalidCipherTextException e) {
            log.severe("CommonEncryption.asymDecrypt(): can't decrypt cipher text:" + e.getMessage());
            throw new TorException("CommonEncryption.asymDecrypt(): InvalidCipherTextException:" + e.getMessage());
        }
    }

    /**
     * Create a fresh RSA key pair.
     * 
     * @return a new RSAKeyPair
     */
    public static RSAKeyPair createNewRSAKeyPair() {
        final int KEY_STRENGTH = 1024;
        final int KEY_CERTAINTY = 80; // use 112 for strength=2048
        try {
            // Generate a 1024-bit RSA key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(KEY_STRENGTH);
            KeyPair keypair = keyGen.genKeyPair();
            RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey)keypair.getPrivate();
            RSAPublicKey publicKey = (RSAPublicKey)keypair.getPublic();
            
            log.info("privateKey="+privateKey);
            log.info("publicKey="+publicKey);
            
            RSAKeyPair result = new RSAKeyPair(publicKey, privateKey);
            return result;
            
         } catch (NoSuchAlgorithmException e) {
            log.log(Level.SEVERE, "Could not create new key pair", e);
            throw new RuntimeException(e);
        }
    }
}
