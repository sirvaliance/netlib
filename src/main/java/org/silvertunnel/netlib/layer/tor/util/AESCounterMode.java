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
package org.silvertunnel.netlib.layer.tor.util;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * implements AES in Countermode. This special mode turn the block cipher into a
 * stream cipher. we thus have to create a key stream and take care that no byte
 * of it gets lost.
 * 
 * @author Lexi Pimenidis
 */
public class AESCounterMode {
    private static final Logger log = Logger.getLogger(AESCounterMode.class.getName());
    
    private final static String ALGORITHM = "AES";
    private final Cipher cipher;
    private int blockSize;
    private byte[] counterBuffer;
    private byte[] streamBuffer;
    private int streamNext;

    /**
     * initialize the AES-Engine
     * 
     * @param encrypt
     *            is the key-stream created with encryption or decryption? In
     *            case of doubt: set to TRUE
     * @param key
     *            the symmetric key for the algorithm
     */
    public AESCounterMode(boolean encrypt, Key key) {
        if (!encrypt) {
            String msg = "AESCounterMode.<init>: WARNING! never use Counter-mode in TOR with 'decryption'";
            log.severe(msg);
            log.log(Level.FINE, msg, new Exception("Exception to log a stack trace"));
        }
        if (key.getEncoded().length!=16) {
            String msg = "AESCounterMode.<init>: HINT: key.length!=16 bytes/128 bits";
            log.warning(msg);
            log.log(Level.FINE, msg, new Exception("Exception to log a stack trace"));
       }

        try {
            // init cipher
            cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key);
            blockSize = cipher.getBlockSize();
    
            // init counter
            counterBuffer = new byte[blockSize];
            streamBuffer = new byte[blockSize];
            streamNext = blockSize;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * initialize the AES-Engine
     * 
     * @param encrypt
     *            is the key-stream created with encryption or decryption? In
     *            case of doubt: set to TRUE
     * @param key
     *            the symmetric key for the algorithm
     */
   public AESCounterMode(boolean encrypt, byte [] key)  {
        this(encrypt, new SecretKeySpec(key, ALGORITHM));
    }

    /**
     * reads the next key of the key stream from the buffer. if the buffer is
     * not filled, generates the next few bytes in the buffer.
     * 
     * @return the next byte of the key stream
     */
    private byte nextStreamByte() {
        ++streamNext;
        // are there still unused bytes in the buffer?
        if (streamNext >= blockSize) {
            // fill stream-buffer
            streamBuffer = cipher.update(counterBuffer);
            streamNext = 0;
            // increase counter
            int j = blockSize - 1;
            do {
                ++counterBuffer[j];
                --j;
            } while ((counterBuffer[j + 1] == 0) && (j >= 0));
        }

        return streamBuffer[streamNext];
    }

    /**
     * encrypts or decrypts an array of arbitrary length. since counter mode is
     * used as a stream cipher, the cipher is symmetric, i.e. encryption and
     * decryption is the same.
     * 
     * @param in
     *            input the plain text, or the cipher text
     * @return receive the result
     */
    public byte[] processStream(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; ++i) {
            byte cipher = nextStreamByte();
            out[i] = (byte) (((int) in[i] + 256) ^ ((int) cipher + 256));
        }

        return out;
    }
}
