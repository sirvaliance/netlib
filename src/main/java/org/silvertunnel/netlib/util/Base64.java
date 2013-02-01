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

/**
 * Support to encode and decode BASE64 Strings.
 * 
 * @author hapke
 */
public class Base64 {
    private static final String UTF8 = "UTF-8";
    
       /**
     * Encode the input data producing a base 64 encoded String.
     * 
     * @param input
     * @return base64 encoded input; null in the case of an error
     */
    public static String encode(byte[] input) {
        try {
            return new String(org.bouncycastle.util.encoders.Base64.encode(input), UTF8);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Decode the base 64 encoded String data.
     * 
     * @param input    encoded in base64
     * @return a byte array representing the decoded data; null in the case of an error
     */
    public static byte[] decode(String input) {
        try {
            return org.bouncycastle.util.encoders.Base64.decode(input);
        } catch (Exception e) {
            return null;
        }
    }
}
