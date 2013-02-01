/**
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
package org.silvertunnel.netlib.layer.tor.circuit;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.layer.tor.directory.RouterImpl;
import org.silvertunnel.netlib.layer.tor.util.AESCounterMode;
import org.silvertunnel.netlib.layer.tor.util.Encoding;
import org.silvertunnel.netlib.layer.tor.util.Encryption;
import org.silvertunnel.netlib.layer.tor.util.TorException;


/**
 * represents a server as part of a specific circuit. Stores the additional data
 * and contains all of the complete crypto-routines.
 * 
 * @author Lexi Pimenidis
 * @author Tobias Koelsch
 */
public class Node {
    private static final Logger log = Logger.getLogger(Node.class.getName());

    /** length of SHA-1 digest in bytes */
    final int DIGEST_LEN = 20;
    
    private RouterImpl router;
    /** used to encrypt a part of the diffie-hellman key-exchange */
    private byte[] symmetricKeyForCreate;
    /** data for the diffie-hellman key-exchange */
    private BigInteger dhPrivate;
    private BigInteger dhX;
    private byte[] dhXBytes;
    private byte[] dhYBytes;
    /** the derived key data */
    private byte[] kh;
    /** digest for all data send to this node */
    private byte[] forwardDigest;
    /** digest for all data received from this node */
    private byte[] backwardDigest;
    /** symmetric key for sending data */
    private byte[] kf; 
    /** symmetric key for receiving data */
    private byte[] kb; 
    private AESCounterMode aesEncrypt;
    private AESCounterMode aesDecrypt;
    private MessageDigest sha1Forward;
    private MessageDigest sha1Backward;

    /** The SKIP 1024 bit modulus */
    static final BigInteger dhP = new BigInteger(
            "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
                    + "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
                    + "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
                    + "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
                    + "49286651ECE65381FFFFFFFFFFFFFFFF", 16);

    /** The base used with the SKIP 1024 bit modulus */
    static final BigInteger dhG = new BigInteger("2");


    /** constructor for (hidden service) server-side.  */
    Node(RouterImpl init,byte[] dhXBytes) {
        if (init == null) {
            throw new NullPointerException("can't init node on NULL server");
        }
        // save a pointer to the server's data
        this.router = init;
        Random rnd = new Random();
        // do Diffie-Hellmann
        dhX = new BigInteger(1,dhXBytes);
        dhPrivate = new BigInteger(dhP.bitLength() - 1, rnd);
        BigInteger dhXY = dhX.modPow(dhPrivate, dhP);
        byte[] dhXYBytes = convertBigIntegerTo128Bytes(dhXY);
        // return dhY-Bytes
        BigInteger dhY = dhG.modPow(dhPrivate, dhP);
        dhYBytes = convertBigIntegerTo128Bytes(dhY);

        // derive key material
        final int NUM_OF_DIGESTS = 5; // TODO: was 3 as specified in spec - but not working
        byte[] k = new byte[NUM_OF_DIGESTS*DIGEST_LEN];
        byte[] sha1Input = new byte[dhXYBytes.length + 1];
        System.arraycopy(dhXYBytes, 0, sha1Input, 0, dhXYBytes.length);
        for (int i = 0; i < NUM_OF_DIGESTS; ++i) {
            sha1Input[sha1Input.length - 1] = (byte) i;
            byte[] singleDigest = Encryption.getDigest(sha1Input);
            System.arraycopy(singleDigest, 0, k, i*DIGEST_LEN, DIGEST_LEN);
        }
        if (log.isLoggable(Level.FINE)) {
            log.fine("Node.<init>: dhX = \n"
                    + Encoding.toHexString(dhXBytes, 100) + "\n" + "dhY = \n"
                    + Encoding.toHexString(dhYBytes, 100) + "\n" + "dhXY = keymaterial:\n"
                    + Encoding.toHexString(dhXYBytes, 100) + "\n" + "Key Data:\n"
                    + Encoding.toHexString(k, 100));
        }

        // derived key info is correct - save to final destination
        // handshake
        kh = new byte[20];
        System.arraycopy(k, 0, kh, 0, 20);
        // backward digest
        backwardDigest = new byte[20];
        System.arraycopy(k, 20, backwardDigest, 0, 20);
        sha1Backward = Encryption.getMessagesDigest();
        sha1Backward.update(backwardDigest, 0, 20);
        // forward digest
        forwardDigest = new byte[DIGEST_LEN];
        System.arraycopy(k, 40, forwardDigest, 0, 20);
        sha1Forward = Encryption.getMessagesDigest();
        sha1Forward.update(forwardDigest, 0, 20);
        // secret key for sending data
        kf = new byte[16];
        System.arraycopy(k, 60, kf, 0, 16);
        aesDecrypt = new AESCounterMode(true, kf);
        // secret key for receiving data
        kb = new byte[16];
        System.arraycopy(k, 76, kb, 0, 16);
        aesEncrypt = new AESCounterMode(true, kb);

        log.fine("Node.<init>: dhX = \n"
                    + Encoding.toHexString(dhXBytes, 100) + "\n" + "dhY = \n"
                    + Encoding.toHexString(dhYBytes, 100) + "\n" + "dhXY = keymaterial:\n"
                    + Encoding.toHexString(dhXYBytes, 100) + "\n" + "Key Data:\n"
                    + Encoding.toHexString(k, 100)+ "\n" + "Key Data kf:\n"
                    + Encoding.toHexString(kf, 100)+ "\n" + "Key Data kb:\n"
                    + Encoding.toHexString(kb, 100));
    }

    /** constructor for client-side */
    public Node(RouterImpl init) {
        if (init == null) {
            throw new NullPointerException("can't init node on NULL server");
        }
        // save a pointer to the server's data
        this.router = init;
        Random rnd = new Random();

        // Diffie-Hellman: generate our secret
        dhPrivate = new BigInteger(dhP.bitLength() - 1, rnd);
        // Diffie-Hellman: generate g^x
        dhX = dhG.modPow(dhPrivate, dhP);
        dhXBytes = convertBigIntegerTo128Bytes(dhX);

        log.fine("Node.<init client>: dhX = \n"
                + Encoding.toHexString(dhXBytes, 100) + "\n" + "dhY = \n"
                + Encoding.toHexString(dhYBytes, 100));

        // generate random symmetric key for circuit creation
        symmetricKeyForCreate = new byte[16];
        rnd.nextBytes(symmetricKeyForCreate);
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
     * @param data
     *            to be encrypted, needs currently to be at least 70 bytes long
     * @return the first half of the key exchange, ready to be send to the other
     *         partner
     */
    byte[] asymEncrypt(byte[] data) throws TorException {
        return Encryption.asymEncrypt(router.getOnionKey(), symmetricKeyForCreate, data);
    }

    /**
     * called after receiving created or extended cell: finished DH-key
     * exchange. Expects the first 148 bytes of the data array to be filled
     * with:<br>
     * <ul>
     * <li>128 bytes of DH-data (g^y)
     * <li>20 bytes of derivated key data (KH) (see chapter 4.2 of torspec)
     * </ul>
     * 
     * @param data
     *            expects the received second half of the DH-key exchange
     */
    public void finishDh(byte[] data) throws TorException {
        // calculate g^xy
        // - fix some undocument stuff: all numbers are 128-bytes only!
        // - add a leading zero to all numbers
        dhYBytes = new byte[128];
        System.arraycopy(data, 0, dhYBytes, 0, 128);
        BigInteger dhY = new BigInteger(1,dhYBytes);
        BigInteger dhXY = dhY.modPow(dhPrivate, dhP);
        byte[] dhXYBytes = convertBigIntegerTo128Bytes(dhXY);

        // derive key material
        final int NUM_OF_DIGESTS = 5;
        byte[] k = new byte[NUM_OF_DIGESTS*DIGEST_LEN];
        byte[] sha1Input = new byte[dhXYBytes.length + 1];
        System.arraycopy(dhXYBytes, 0, sha1Input, 0, dhXYBytes.length);
        for (int i = 0; i < NUM_OF_DIGESTS; ++i) {
            sha1Input[sha1Input.length - 1] = (byte) i;
            byte[] singleDigest = Encryption.getDigest(sha1Input);
            System.arraycopy(singleDigest, 0, k, i*DIGEST_LEN, DIGEST_LEN);
        }
        if (log.isLoggable(Level.FINE)) {
           log.fine("Node.finishDh: dhX = \n"
                    + Encoding.toHexString(dhXBytes, 100) + "\n" + "dhY = \n"
                    + Encoding.toHexString(dhYBytes, 100) + "\n" + "dhXY = keymaterial:\n"
                    + Encoding.toHexString(dhXYBytes, 100) + "\n" + "Key Data:\n"
                    + Encoding.toHexString(k, 100));
        }
 
        // check if derived key data is equal to bytes 128-147 of data[]
        boolean equal = true;
        for (int i = 0; equal && (i < 20); ++i) {
            equal = (k[i] == data[128 + i]);
        }
        // is there some error in the key data?
        if (!equal) {
            throw new TorException("derived key material is wrong!");
        }

        // derived key info is correct - save to final destination
        // handshake
        kh = new byte[20];
        System.arraycopy(k, 0, kh, 0, 20);
        // forward digest
        forwardDigest = new byte[DIGEST_LEN];
        System.arraycopy(k, 20, forwardDigest, 0, 20);
        sha1Forward = Encryption.getMessagesDigest();
        sha1Forward.update(forwardDigest, 0, 20);
        // backward digest
        backwardDigest = new byte[20];
        System.arraycopy(k, 40, backwardDigest, 0, 20);
        sha1Backward = Encryption.getMessagesDigest();
        sha1Backward.update(backwardDigest, 0, 20);
        // secret key for sending data
        kf = new byte[16];
        System.arraycopy(k, 60, kf, 0, 16);
        aesEncrypt = new AESCounterMode(true, kf);
        // secret key for receiving data
        kb = new byte[16];
        System.arraycopy(k, 76, kb, 0, 16);
        aesDecrypt = new AESCounterMode(true, kb);
        
        log.fine("Node.finishDh: dhX = \n"
                + Encoding.toHexString(dhXBytes, 100) + "\n" + "dhY = \n"
                + Encoding.toHexString(dhYBytes, 100) + "\n" + "dhXY = keymaterial:\n"
                + Encoding.toHexString(dhXYBytes, 100) + "\n" + "Key Data:\n"
                + Encoding.toHexString(k, 100)+ "\n" + "Key Data kf:\n"
                + Encoding.toHexString(kf, 100)+ "\n" + "Key Data kb:\n"
                + Encoding.toHexString(kb, 100));
    }

    /**
     * calculate the forward digest
     * 
     * @param data
     * @return a four-byte array containing the digest
     */
    byte[] calcForwardDigest(byte[] data) {
        if (log.isLoggable(Level.FINER)) {
            log.finer("Node.calcForwardDigest() on:\n" + Encoding.toHexString(data, 100));
        }
        sha1Forward.update(data, 0, data.length);
        byte[] digest = Encryption.intermediateDigest(sha1Forward);
        log.fine(" result:\n" + Encoding.toHexString(digest, 100));
        byte[] fourBytes = new byte[4];
        System.arraycopy(digest, 0, fourBytes, 0, 4);
        return fourBytes;
    }

    /**
     * calculate the backward digest
     * 
     * @param data
     * @return a four-byte array containing the digest
     */
    byte[] calcBackwardDigest(byte[] data) {
        if (log.isLoggable(Level.FINER)) {
            log.finer("Node.calcBackwardDigest() on:\n" + Encoding.toHexString(data, 100));
        }
        sha1Backward.update(data, 0, data.length);
        byte[] digest = Encryption.intermediateDigest(sha1Backward);
        log.finer(" result:\n" + Encoding.toHexString(digest, 100));
        byte[] fourBytes = new byte[4];
        System.arraycopy(digest, 0, fourBytes, 0, 4);
        return fourBytes;
    }

    /**
     * encrypt data with symmetric key
     * 
     * @param data
     *            is used for input and output.
     */
    void symEncrypt(byte[] data) {
        if (log.isLoggable(Level.FINE)) {
            log.fine("Node.symEncrypt for node " + router.getNickname());
        }
        if (log.isLoggable(Level.FINER)) {
            log.finer("Node.symEncrypt in:\n" + Encoding.toHexString(data, 100));
        }

        // encrypt data
        byte[] encrypted = aesEncrypt.processStream(data);
        // copy to output
        if (encrypted.length > data.length) {
            System.arraycopy(encrypted, 0, data, 0, data.length);
        } else {
            System.arraycopy(encrypted, 0, data, 0, encrypted.length);
        }

        if (log.isLoggable(Level.FINER)) {
            log.finer("Node.symEncrypt out:\n" + Encoding.toHexString(data, 100));
        }
    }

    /**
     * decrypt data with symmetric key
     * 
     * @param data
     *            is used for input and output.
     */
    void symDecrypt(byte[] data) {
        if (log.isLoggable(Level.FINE)) {
            log.fine("Node.symDecrypt for node " + router.getNickname());
            /* log.fine("Node.symDecrypt in:\n" + Encoding.toHexString(data, 100)); */
        }

        // decrypt data
        byte[] decrypted = aesDecrypt.processStream(data);
        // copy to output
        if (decrypted.length > data.length) {
            System.arraycopy(decrypted, 0, data, 0, data.length);
        } else {
            System.arraycopy(decrypted, 0, data, 0, decrypted.length);
        }

        /*log.fine( "Node.symDecrypt out:\n" + Encoding.toHexString(data, 100)); */
    }

    /** helper function to convert a bigInteger to a fixed-sized array for TOR-Usage */
    private byte[] convertBigIntegerTo128Bytes(BigInteger a) {
        byte[] temp = a.toByteArray();
        byte[] result = new byte[128];
        if (temp.length > 128) {
            System.arraycopy(temp, temp.length - 128, result, 0, 128);
        } else {
            System.arraycopy(temp, 0, result, 128 - temp.length, temp.length);
        }
        return result;
    }
    
    ///////////////////////////////////////////////////////
    // getters and setters
    ///////////////////////////////////////////////////////
    
    public RouterImpl getRouter() {
        return router;
    }

    public byte[] getSymmetricKeyForCreate() {
        return symmetricKeyForCreate;
    }

    public BigInteger getDhPrivate() {
        return dhPrivate;
    }

    public BigInteger getDhX() {
        return dhX;
    }

    public byte[] getDhXBytes() {
        return dhXBytes;
    }

    public byte[] getDhYBytes() {
        return dhYBytes;
    }

    public byte[] getKh() {
        return kh;
    }

    public byte[] getForwardDigest() {
        return forwardDigest;
    }

    public byte[] getBackwardDigest() {
        return backwardDigest;
    }

    public byte[] getKf() {
        return kf;
    }

    public byte[] getKb() {
        return kb;
    }

    public AESCounterMode getAesEncrypt() {
        return aesEncrypt;
    }

    public AESCounterMode getAesDecrypt() {
        return aesDecrypt;
    }

    public static BigInteger getDhP() {
        return dhP;
    }

    public static BigInteger getDhG() {
        return dhG;
    }
    
}
