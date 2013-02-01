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
package org.silvertunnel.netlib.layer.tor;

import static org.junit.Assert.assertEquals;

import java.util.logging.Logger;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.silvertunnel.netlib.api.HttpTestUtil;
import org.silvertunnel.netlib.api.util.IpNetAddress;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.util.HttpUtil;

import ch.unibe.jexample.Given;
import ch.unibe.jexample.JExample;

/**
 * Test the support of .exit host names to specify Tor exit nodes.
 * 
 * @author hapke
 */
@RunWith(JExample.class)
public class TorExitHostnameRemoteTest extends TorRemoteAbstractTest {
    private static final Logger log = Logger.getLogger(TorExitHostnameRemoteTest.class.getName());

    // our exit node: chaoscomputerclub10
    //private static final String OUR_EXITNODE_HEX_DIGEST = "11A0239FC6668705F68842811318B669C636F86E";
    //private static final String OUR_EXITNODE_IP = "62.113.219.3";
    
    // our exit node: chaoscomputerclub3
    //   parameters found with: grep -A 9 chaoscomputerclub3 /tmp/st-directory-cached-router-descriptors.txt
    private static final String OUR_EXITNODE_HEX_DIGEST = "7610BBD3F5BB67284EEE8476721AE6109DC29BEA";
    private static final String OUR_EXITNODE_IP = "80.237.226.73";
    
    @Test(timeout=600000)
    public void initializeTor() throws Exception {
        // repeat method declaration here to be the first test method of the class
        super.initializeTor();
    }
        
    @Test(timeout=15000)
    @Given("#initializeTor")
    public void testWithHostname() throws Exception {
        final String HOSTNAME = HttpUtil.HTTPTEST_SERVER_NAME+"."+OUR_EXITNODE_HEX_DIGEST+".exit";
        final TcpipNetAddress NETADDRESS = new TcpipNetAddress(HOSTNAME, HttpUtil.HTTPTEST_SERVER_PORT);
        
        // determine exit node id
        IpNetAddress exitNodeIp = HttpTestUtil.getSourceIpNetAddress(torNetLayer, NETADDRESS, "/httptest/bigtest.jsp");
        
        // check result
        assertEquals("wrong exit node IP determined", new IpNetAddress(OUR_EXITNODE_IP), exitNodeIp);
    }
    
    /*
    @Test(timeout=15000)
    @Given("#initializeTor")
    public void testWithHostname2() throws Exception {
        testWithHostname();
    }
    */
}
