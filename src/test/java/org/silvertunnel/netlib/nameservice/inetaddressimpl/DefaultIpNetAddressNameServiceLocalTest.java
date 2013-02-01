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

package org.silvertunnel.netlib.nameservice.inetaddressimpl;


import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import org.junit.Test;
import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.util.IpNetAddress;

/**
 * Test of DefaultIpNetAddressNameService.
 * 
 * @author hapke
 */
public class DefaultIpNetAddressNameServiceLocalTest {
    private static final Logger log = Logger.getLogger(DefaultIpNetAddressNameServiceLocalTest.class.getName());
    
    private static final String TEST_HOSTNAME = "localhost";
    private static final IpNetAddress TEST_IP = new IpNetAddress("127.0.0.1"); 

    /**
     * Test host name (localhost) -> IP (127.0.0.1) mapping.
     * @throws Exception
     */
    @Test
    public void testLocalhostLookupAddress() throws Exception {
        DefaultIpNetAddressNameService ns = new DefaultIpNetAddressNameService();
        NetAddress[] resolvedIps = ns.getAddressesByName(TEST_HOSTNAME);
        
        // make the resolvedIps unique
        Set<NetAddress> uniqueResolvedIps = new HashSet<NetAddress>(Arrays.asList(resolvedIps));
        
        assertEquals("wrong number of IPs found", 1, uniqueResolvedIps.size());
        assertEquals("wrong IP found", TEST_IP, resolvedIps[0]);
    }
    
    /**
     * Test IP (127.0.0.1) -> host name (localhost) mapping.
     * @throws Exception
     */
    @Test
    public void testLocalhostLookupName() throws Exception {
        DefaultIpNetAddressNameService ns = new DefaultIpNetAddressNameService();
        String[] resolvedNames = ns.getNamesByAddress(TEST_IP);
        assertEquals("wrong number of names found", 1, resolvedNames.length);
        assertEquals("wrong name found", TEST_HOSTNAME, resolvedNames[0]);
    }
}
