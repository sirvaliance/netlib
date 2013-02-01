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
package org.silvertunnel.netlib.adapter.nameservice;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetAddressNameService;
import org.silvertunnel.netlib.api.util.IpNetAddress;
import org.silvertunnel.netlib.nameservice.mock.MockNetAddressNameService;

import ch.unibe.jexample.Given;
import ch.unibe.jexample.JExample;

/**
 * JUnit test cases to test NameServiceGlobalUtil and the NameService adapter.
 * 
 * @author hapke
 */
@RunWith(JExample.class)
public class WithNetlibNameServiceLocalTest {
    private static final Logger log = Logger.getLogger(WithNetlibNameServiceLocalTest.class.getName());
    
    private static final String MOCK_HOSTNAME1 = "dnstest.silvertunnel.org";
    private static final IpNetAddress MOCK_IP1 = new IpNetAddress("44.11.33.22");
    
    private static final String MOCK_HOSTNAME2 = "dnstest2.silvertunnel.org";
    private static final IpNetAddress MOCK_IP2 = new IpNetAddress("88.66.77.56");

    /** field to store a Throwable thrown in the static constructor to throw it later (in a test method) */
    private static Throwable throwableOfStaticInitializer;
    
    /**
     * Install NetlibNameService.
     * 
     * Do not use Junit's @org.junit.Before because this is too late.
     */
    static {
        log.info("static init");
        try {
            NameServiceGlobalUtil.initNameService();
        } catch (Throwable t) {
            throwableOfStaticInitializer = t;
        }
    }
    
    /**
     * Check that the NopNetAddressNameService is really used after setup.
     */
    @Test(timeout=5000)
    public void testWithNopNetAddressNameService() throws Throwable {
        log.info("testWithNopNetAddressNameService()");
        if (throwableOfStaticInitializer!=null) {
            throw throwableOfStaticInitializer;
        }

        try {
            // try to use Java standard way of DNS resolution
            InetAddress result1 = InetAddress.getAllByName(MOCK_HOSTNAME1)[0];
            // we should not reach this code because name resolution should fail
            fail(MOCK_HOSTNAME1+" could be resolved to "+result1+" (was not expected) - this probably means that the NetlibNameService was not used but the Internet instead");

        } catch (UnknownHostException e) {
            // this is expected
        }
    }
    
    /**
     * Check that we can switch to an alternative NetAddressNameService (to the MockNetAddressNameService).
     */
    @Test(timeout=15000)
    @Given("#testWithNopNetAddressNameService")
    public void testWithMockNetAddressNameService() throws Throwable {
        log.info("testWithMockNetAddressNameService()");
        if (throwableOfStaticInitializer!=null) {
            throw throwableOfStaticInitializer;
        }

        //
        // switch to MockNetAddressNameService
        //
        Map<String,NetAddress> name2AddressMapping = new HashMap<String,NetAddress>();
        Map<NetAddress,String> address2NameMapping = new HashMap<NetAddress,String>();
        name2AddressMapping.put(MOCK_HOSTNAME1, MOCK_IP1);
        NetAddressNameService ns = new MockNetAddressNameService(name2AddressMapping, address2NameMapping);
        NameServiceGlobalUtil.setIpNetAddressNameService(ns);
 
        // circumvent caching
        Thread.sleep(NameServiceGlobalUtil.getCacheTimeoutMillis());
        
        //
        // check that dnstest.silvertunnel.org can be resolved now 
        //   and that dnstest2.silvertunnel.org cannot be resolved
        //
        try {
            // try to use Java standard way of DNS resolution
            InetAddress result1 = InetAddress.getAllByName(MOCK_HOSTNAME1)[0];
            assertEquals(MOCK_HOSTNAME1+" resolved to wrong address", MOCK_IP1, new IpNetAddress(result1));

        } catch (UnknownHostException e) {
            fail("resolution of "+MOCK_HOSTNAME1+" failed, but it should be resolved to "+MOCK_IP1);
        }

        try {
            // try to use Java standard way of DNS resolution
            InetAddress result2 = InetAddress.getAllByName(MOCK_HOSTNAME2)[0];
            // we should not reach this code because name resolution should fail
            fail(MOCK_HOSTNAME2+"resolved to "+result2+" (was not expected)");

        } catch (UnknownHostException e) {
            // this is expected
        }
    }
    
    /**
     * Check that we can switch to an alternative NetAddressNameService (to the MockNetAddressNameService).
     */
    @Test(timeout=15000)
    @Given("#testWithMockNetAddressNameService")
    public void testWithMockNetAddressNameService2() throws Throwable {
        log.info("testWithMockNetAddressNameService2()");
        if (throwableOfStaticInitializer!=null) {
            throw throwableOfStaticInitializer;
        }

        //
        // switch to 2nd MockNetAddressNameService
        //
        Map<String,NetAddress> name2AddressMapping = new HashMap<String,NetAddress>();
        Map<NetAddress,String> address2NameMapping = new HashMap<NetAddress,String>();
        name2AddressMapping.put(MOCK_HOSTNAME2, MOCK_IP2);
        NetAddressNameService ns = new MockNetAddressNameService(name2AddressMapping, address2NameMapping);
        NameServiceGlobalUtil.setIpNetAddressNameService(ns);
 
        // circumvent caching
        Thread.sleep(NameServiceGlobalUtil.getCacheTimeoutMillis());
       
        //
        // check that dnstest.silvertunnel.org can be resolved now 
        //   and that dnstest2.silvertunnel.org cannot be resolved
        //
        try {
            // try to use Java standard way of DNS resolution
            InetAddress result1 = InetAddress.getAllByName(MOCK_HOSTNAME1)[0];
            // we should not reach this code because name resolution should fail
            fail(MOCK_HOSTNAME1+"resolved to "+result1+" (was not expected)");

        } catch (UnknownHostException e) {
            // this is expected
        }

        try {
            // try to use Java standard way of DNS resolution
            InetAddress result2 = InetAddress.getAllByName(MOCK_HOSTNAME2)[0];
            assertEquals(MOCK_HOSTNAME2+" resolved to wrong address", MOCK_IP2, new IpNetAddress(result2));

        } catch (UnknownHostException e) {
            fail("resolution of "+MOCK_HOSTNAME2+" failed, but it should be resolved to "+MOCK_IP2);
        }
    }
}
