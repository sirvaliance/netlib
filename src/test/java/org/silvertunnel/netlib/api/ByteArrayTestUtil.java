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

package org.silvertunnel.netlib.api;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.logging.Logger;

import org.silvertunnel.netlib.util.ByteArrayUtil;

/**
 * Utilities to handle input streams, output streams and byte arrays.
 * 
 * @author hapke
 */
public class ByteArrayTestUtil {
    private static final Logger log = Logger.getLogger(ByteArrayTestUtil.class.getName());

    /**
     * Read expectedResponse.length number of bytes from responseIS and compare it with the expectedResponse.
     * 
     * @param log     if null: do not log
     * @param msg
     * @param expectedResponse
     * @param actualResponseIS
     * @throws IOException
     */
    public static void assertByteArrayFromInputStream(Logger log, String msg, byte[] expectedResponse, InputStream actualResponseIS) throws IOException {
        // read the expected number of bytes
        byte[] response = new byte[expectedResponse.length];
        int expLen = expectedResponse.length;
        for (int i=0; i<expLen; i++) {
            response[i] = (byte)actualResponseIS.read();
            if (log!=null) {
                log.info("  read response["+i+"/"+(expLen-1)+"]="+
                        response[i]         + "('"+ByteArrayUtil.asChar(response[i])+"') , expected: " + 
                        expectedResponse[i] + "('"+ByteArrayUtil.asChar(expectedResponse[i])+"')");
            }
        }
    
        ByteArrayTestUtil.assertEquals("wrong response", expectedResponse, response);
    }

    public static void assertEquals(String msg, byte[] expected, byte[] actual) {
        String expectedStr = Arrays.toString(expected);
        String actualStr = Arrays.toString(actual);
        org.junit.Assert.assertEquals(msg, expectedStr, actualStr);
    }

}
