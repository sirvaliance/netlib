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
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.silvertunnel.netlib.api.util.IpNetAddress;
import org.silvertunnel.netlib.nameservice.mock.NopNetAddressNameService;

import ch.unibe.jexample.Given;
import ch.unibe.jexample.JExample;

/**
 * JUnit test case(s) to test that NameServiceGlobalUtil and the NameService adapter
 * are not working it not requested
 * 
 * @author hapke
 */
@RunWith(JExample.class)
public class WithoutNetlibNameServiceLocalTest {
    private static final Logger log = Logger.getLogger(WithoutNetlibNameServiceLocalTest.class.getName());
    
    private static final String HOSTNAME1 = "dnstest.silvertunnel.org";
    private static final IpNetAddress IP1 = new IpNetAddress("1.2.3.4");

    private static final String HOSTNAME2 = "dnstest2.silvertunnel.org";
    private static final IpNetAddress IP2 = new IpNetAddress("5.6.7.8");
    
    /**
     * Check that DNS requests work.
     */
    @Test(timeout=15000)
    public void testWithoutAnyChange() {
        log.info("testWithoutAnyChange()");

        // try to use Java standard way of DNS resolution
        try {
            InetAddress result1 = InetAddress.getAllByName(HOSTNAME1)[0];
            assertEquals(HOSTNAME1+" resolved to wrong address", IP1, new IpNetAddress(result1));

        } catch (UnknownHostException e) {
            fail("resolution of "+HOSTNAME1+" failed, but it should be resolved to "+IP1);
        }
    }

    
    /**
     * Test that lower NetAddressNameService cannot be switched
     * (i.e. because no Netlib NameService adapter is installed).
     */
    @Test(timeout=2000)
    @Given("#testWithoutAnyChange")
    public void testThat_NameServiceGlobalUtil_setIpNetAddressNameService_doesNotWork() {
        log.info("testThat_NameServiceGlobalUtil_setIpNetAddressNameService_doesNotWork()");
        
        // try to switch lower NetAddressNameService
        try {
            NameServiceGlobalUtil.setIpNetAddressNameService(new NopNetAddressNameService());
            
            fail("NameServiceGlobalUtil.setIpNetAddressNameService() did not throw an IllegalStateException (but expected)");

        } catch (IllegalStateException e) {
            // exception is expected
            log.log(Level.INFO, "Ingnore Exception: "+e);
        }
        
        // try to use Java standard way of DNS resolution
        try {
            InetAddress result1 = InetAddress.getAllByName(HOSTNAME2)[0];
            assertEquals(HOSTNAME2+" resolved to wrong address", IP2, new IpNetAddress(result1));

        } catch (UnknownHostException e) {
            fail("resolution of "+HOSTNAME2+" failed, but it should be resolved to "+IP2+
                 " - maybe the lower NetAddressNameService was switched (but not expected)");
        }
    }
    
    @Test(timeout=2000)
    @Given("#testThat_NameServiceGlobalUtil_setIpNetAddressNameService_doesNotWork")
    public void testThat_NameServiceGlobalUtil_init_doesNotWork() throws Exception {
        log.info("testThat_NameServiceGlobalUtil_init_doesNotWork()");
        
        InetAddress.getLocalHost();
        try {
            // we expect the following command to fail because of the included self-checker: 
            NameServiceGlobalUtil.initNameService();
            
            fail("NameServiceGlobalUtil.initNameService() did not throw an IllegalStateException (but expected)");
        } catch (IllegalStateException e) {
            // expected
        }
    }
}
