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

import static org.junit.Assert.assertTrue;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;

import org.junit.Test;

/**
 * Test cryptography logic.
 * 
 * @author hapke
 */
public class CryptographyLocalTest {
    private static final Logger log = Logger.getLogger(CryptographyLocalTest.class.getName());
    
    /** any data for testing */
    private static byte[] data; 

    static {
        try {
            data = "lnx2389rfh5kfjnec974rfcne2fckjencrf95p9fuj. leekcnx4o8tgcup0tjcelgkcn509gcj6lgnw5-bkn;".getBytes("UTF-8"); 
        } catch (Exception e) {
            log.log(Level.SEVERE, "could not initialize class CryptographyLocalTest", e);
        }
    }
    
    @Test
    public void testSignatures() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, new SecureRandom());
        KeyPair keypair = keyPairGenerator.generateKeyPair(); 
        assertTrue(Encryption.verifySignature(Encryption.signData(data, keypair.getPrivate()), keypair.getPublic(), data));
    }

    @Test
    public void testSymmetricEncryption() throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128, new SecureRandom());
        Key key = keyGenerator.generateKey();
        byte[] decrypted = new AESCounterMode(true, key).processStream(new AESCounterMode(true, key).processStream(data));
        assertTrue(Arrays.equals(decrypted, data));
    }
    
    @Test
    public void testSha1Cloning() throws GeneralSecurityException, CloneNotSupportedException {
        MessageDigest digest = MessageDigest.getInstance(Encryption.DIGEST_ALGORITHM);
        digest.update(data, 0, data.length);
        
        byte[] digest1 = ((MessageDigest) digest.clone()).digest();
        byte[] digest2 = ((MessageDigest) digest.clone()).digest();
        assertTrue(Arrays.equals(digest1, digest2));
    }

    /* TODO: remove if not needed (see also class Encryption): 
    @Test
    public void testAsymmetricEncryption() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, new SecureRandom());
        KeyPair keypair = keyPairGenerator.generateKeyPair(); 
        final byte[] symmetric_key_for_create = new byte[16];
        new Random().nextBytes(symmetric_key_for_create);
        byte[] plaintext = new byte[100];
        new Random().nextBytes(plaintext);
        byte[] ciphertext = Encryption.asymmetricEncrypt(plaintext, symmetric_key_for_create, keypair.getPublic());
        byte[] newplaintext = Encryption.asymmetricDecrypt(ciphertext, symmetric_key_for_create, keypair.getPrivate());
        assertTrue(Arrays.equals(newplaintext, plaintext));
    }
    */
}
