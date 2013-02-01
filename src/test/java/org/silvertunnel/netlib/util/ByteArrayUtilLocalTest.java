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

package org.silvertunnel.netlib.util;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.junit.Test;

/**
 * Test of class ByteArrayUtil.
 * 
 * @author hapke
 */
public class ByteArrayUtilLocalTest {
   
    @Test(timeout=2000)
    public void testConcatByteArrays() {
        final byte[] a1 = {1, 2, 3};
        final byte[] a2 = {};
        final byte[] a3 = {11, 22};
        final byte[] a4 = {-1};
        byte[] result = ByteArrayUtil.concatByteArrays(a1, a2, a3, a4);
        assertEquals("wrong concatByteArrays() result", Arrays.toString(new byte[] {1, 2, 3, 11, 22, -1}), Arrays.toString(result));
    }
}
