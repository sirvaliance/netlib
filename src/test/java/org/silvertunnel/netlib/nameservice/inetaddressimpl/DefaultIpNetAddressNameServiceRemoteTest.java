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
import static org.junit.Assert.fail;

import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.logging.Logger;

import org.junit.Test;
import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.util.IpNetAddress;

/**
 * Test of DefaultIpNetAddressNameService.
 * 
 * Similar test cases:
 * @see org.silvertunnel.netlib.nameservice.tor.TorNetAddressNameServiceRemoteTest
 * 
 * @author hapke
 */
public class DefaultIpNetAddressNameServiceRemoteTest {
    private static final Logger log = Logger.getLogger(DefaultIpNetAddressNameServiceRemoteTest.class.getName());
    
    private static final String TEST1_HOSTNAME = "dnstest.silvertunnel.org";
    private static final IpNetAddress TEST1_IP = new IpNetAddress("1.2.3.4"); 
    private static final String TEST2_HOSTNAME = "dnstest2.silvertunnel.org";
    private static final IpNetAddress TEST2_IP = new IpNetAddress("5.6.7.8"); 
    private static final String TEST3_HOSTNAME = "google-public-dns-a.google.com";
    private static final IpNetAddress TEST3_IP = new IpNetAddress("8.8.8.8");
    private static final String TEST_INVALID_HOSTNAME = "silvertunnel-no-dns-entry.org";

    /**
     * Test host name -> IP mapping for dnstest.silvertunnel.org.
     * 
     * @throws Exception
     */
    @Test
    public void testGetAddressesByName() throws Exception {
        DefaultIpNetAddressNameService ns = new DefaultIpNetAddressNameService();
        NetAddress[] resolvedIps = ns.getAddressesByName(TEST1_HOSTNAME);
        assertEquals("wrong number of IPs found", 1, resolvedIps.length);
        assertEquals("wrong IP found", TEST1_IP, resolvedIps[0]);
    }
    
    /**
     * Test host name -> IP mapping for dnstest2.silvertunnel.org.
     * 
     * @throws Exception
     */
    @Test
    public void testGetAddressesByName2() throws Exception {
        DefaultIpNetAddressNameService ns = new DefaultIpNetAddressNameService();
        NetAddress[] resolvedIps = ns.getAddressesByName(TEST2_HOSTNAME);
        assertEquals("wrong number of IPs found", 1, resolvedIps.length);
        assertEquals("wrong IP found", TEST2_IP, resolvedIps[0]);
    }
    
    /**
     * Test IP -> host name mapping for 127.0.0.1.
     * 
     * @throws Exception
     */
    @Test
    public void testGetNamesByAddress() throws Exception {
        DefaultIpNetAddressNameService ns = new DefaultIpNetAddressNameService();
        String[] resolvedNames = ns.getNamesByAddress(TEST3_IP);
        assertEquals("wrong number of names found", 1, resolvedNames.length);
        assertEquals("wrong name found", TEST3_HOSTNAME, resolvedNames[0]);
    }

    /**
     * Test host name -> IP mapping for silvertunnel-no-dns-entry.org.
     * 
     * @throws Exception
     */
    @Test
    public void testGetAddressesByNameInvalid() throws Exception {
        DefaultIpNetAddressNameService ns = new DefaultIpNetAddressNameService();
        try {
            NetAddress[] resolvedIps = ns.getAddressesByName(TEST_INVALID_HOSTNAME);
            
            // this should not be executed:
            String resolvedIpsStr = (resolvedIps==null) ? null : Arrays.toString(resolvedIps);
            fail("expected UnknownHostException not thrown, resolvedIps="+resolvedIpsStr);
            
        } catch (UnknownHostException e) {
            // expected
        }
    }
}
