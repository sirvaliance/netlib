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

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.logging.Logger;

import org.junit.Test;

/**
 * Test cryptography logic.
 * 
 * @author hapke
 */
public class EncodingLocalTest {
    private static final Logger log = Logger.getLogger(EncodingLocalTest.class.getName());
    
    /** any data for testing */
    private static final byte[] EXAMPLE_DATA = {-11, 22, -33, 44, -55, 66, -77, 88, -99}; 

    @Test
    public void testToBase32() {
        String result = Encoding.toBase32(EXAMPLE_DATA);
        assertEquals("wrong toBase32() result", "6uln6lgjikzvrhi", result);
    }

    @Test
    public void testParseBase32() {
        String base32 = Encoding.toBase32(EXAMPLE_DATA);
        byte[] result = Encoding.parseBase32(base32);
        assertEquals("wrong parseBase32() result", Arrays.toString(EXAMPLE_DATA), Arrays.toString(result));
    }
    
    @Test
    public void testIntTo4ByteArray1() {
        int value = 0xfc00ee11;
        byte[] result = Encoding.intToNByteArray(value, 4);
        assertEquals("wrong intToNByteArray() (1) result", Arrays.toString(new byte[] {(byte)0xfc, (byte)0x00, (byte)0xee, (byte)0x11}), Arrays.toString(result));
    }

    @Test
    public void testIntTo4ByteArray2() {
        int value = 0x11fc00ee;
        byte[] result = Encoding.intToNByteArray(value, 4);
        assertEquals("wrong intToNByteArray() (2) result", Arrays.toString(new byte[] {(byte)0x11, (byte)0xfc, (byte)0x00, (byte)0xee}), Arrays.toString(result));
    }
}
