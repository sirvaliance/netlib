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

import org.junit.Test;

/**
 * Test of class HttpUtil.
 * 
 * @author hapke
 */
public class HttpUtilLocalTest {
    private static final String UTF8 = "UTF-8";
    
    @Test(timeout=1000)
    public void testdecodeChunkedHttpResponse1() throws Exception {
        String chunked = "14\n\rHalloHalloHalloHallo\n\r0\n\r";
        String expectedUnchunked = "HalloHalloHalloHallo";
        
        assertEquals("wrong result",
                expectedUnchunked,
                new String(HttpUtil.getInstance().decodeChunkedHttpResponse(chunked.getBytes(UTF8))));
    }

    @Test(timeout=1000)
    public void testdecodeChunkedHttpResponse2() throws Exception {
        String chunked = "9\nHallo\nIhr\n1\n\n3\nda!\n0\n";
        String expectedUnchunked = "Hallo\nIhr\nda!";
        
        assertEquals("wrong result",
                expectedUnchunked,
                new String(HttpUtil.getInstance().decodeChunkedHttpResponse(chunked.getBytes(UTF8))));
    }
}
