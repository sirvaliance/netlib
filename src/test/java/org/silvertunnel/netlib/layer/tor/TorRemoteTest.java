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

import static org.junit.Assert.fail;

import java.util.Collection;
import java.util.logging.Logger;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.silvertunnel.netlib.api.HttpTestUtil;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.layer.tor.api.Router;
import org.silvertunnel.netlib.util.ByteArrayUtil;
import org.silvertunnel.netlib.util.HttpUtil;

import ch.unibe.jexample.Given;
import ch.unibe.jexample.JExample;

/**
 * Test Tor's basic features.
 * 
 * @author hapke
 */
@RunWith(JExample.class)
public class TorRemoteTest extends TorRemoteAbstractTest {
    private static final Logger log = Logger.getLogger(TorRemoteTest.class.getName());

    @Test(timeout=600000)
    public void initializeTor() throws Exception {
        // repeat method declaration here to be the first test method of the class
        super.initializeTor();
    }
        
    @Test(timeout=15000)
    @Given("#initializeTor")
    public void testWithHostname() throws Exception {
        // create connection
        NetSocket topSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR_OVER_TLS_OVER_TCPIP).
            createNetSocket(null, null, HttpUtil.HTTPTEST_SERVER_NETADDRESS);

        // use open socket to execute HTTP request and to check the response
        HttpTestUtil.executeSmallTest(topSocket, "testTorWithHostname", 10000);
    }
    @Test(timeout=15000)
    @Given("#initializeTor")
    public void testWithHostname2() throws Exception {
        testWithHostname();
    }
    
    @Test(timeout=15000)
    @Given("#initializeTor")
    public void testWithIPAddress() throws Exception {
        // create connection
        NetSocket topSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR_OVER_TLS_OVER_TCPIP).
            createNetSocket(null, null, new TcpipNetAddress(new byte[] {(byte)178, (byte)77, (byte)97, (byte)221}, 80));
    

        // use open socket to execute HTTP request and to check the response
        HttpTestUtil.executeSmallTest(topSocket, "testTorWithIPAddress", 10000);
    }
    @Test(timeout=15000)
    @Given("#initializeTor")
    public void testWithIPAddress2() throws Exception {
        testWithIPAddress();
    }

    @Ignore
    @Test(timeout=30000)
    @Given("#initializeTor")
    public void testDownloadPerformance() throws Exception {
        NetSocket topSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR_OVER_TLS_OVER_TCPIP).
            createNetSocket(null, null, HttpUtil.HTTPTEST_SERVER_NETADDRESS);
        
        // use open socket for to execute HTTP request and to check the response
        // (download of file of size 100,000 bytes in max 25s = 32kbit/s = 4KByte/s)
        HttpTestUtil.executeDownloadTest(topSocket, 25000);
        topSocket.close();
    }
    @Ignore
    @Test(timeout=30000)
    @Given("#initializeTor")
    public void testDownloadPerformance2() throws Exception {
        testDownloadPerformance();
    }    

    @Ignore(value="this service is not always on")
    @Test(timeout=15000)
    @Given("#initializeTor")
    public void testThatRequestGoesThroughTorNetwork() throws Exception  {
        final String TORCHECK_HOSTNAME = "torcheck.xenobite.eu";
        final TcpipNetAddress TORCHECK_NETADDRESS = new TcpipNetAddress(TORCHECK_HOSTNAME, 80);
        
        // create connection
        NetSocket topSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR_OVER_TLS_OVER_TCPIP).
            createNetSocket(null, null, TORCHECK_NETADDRESS);

        // communicate with the remote side
        byte[] httpResponse = HttpUtil.getInstance().get(
                topSocket, TORCHECK_NETADDRESS, "/", 5000);
        String httpResponseStr = ByteArrayUtil.showAsString(httpResponse);
        log.info("http response body: "+ httpResponseStr);
        
        // make the httpResponseStr readable in HTML reports
        httpResponseStr = removeHtmlTags(httpResponseStr);
        
        // trivial check
        final int MIN_RESONSE_LEN = 100;
        if (httpResponseStr==null || httpResponseStr.length()<MIN_RESONSE_LEN) {
            fail("invalid/short HTTP response body="+httpResponseStr);
        }
        
        // check result
        final String SUCCESS_STR = "Your IP is identified to be a Tor-EXIT.";
        final String PROBABLY_SUCCESS_STR = "Your IP is identified to be a Tor-Node.";
        final String PROBABLY_SUCCESS_STR2 = "Congratulations. Your browser is configured to use Tor.";
        if (!httpResponseStr.contains(SUCCESS_STR) &&
                !httpResponseStr.contains(PROBABLY_SUCCESS_STR) &&
                !httpResponseStr.contains(PROBABLY_SUCCESS_STR2)) {
            fail("The request did NOT go through Tor network, see response body for details = "+httpResponseStr);
        }

        ///////////////////////////////////////////////////
        // crosscheck
        ///////////////////////////////////////////////////

        // create connection
        NetSocket topSocket2 = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP).
            createNetSocket(null, null, TORCHECK_NETADDRESS);

        // communicate with the remote side
        byte[] httpResponse2 = HttpUtil.getInstance().get(
                topSocket2, TORCHECK_NETADDRESS, "/", 5000);
        String httpResponseStr2 = ByteArrayUtil.showAsString(httpResponse2);
        log.info("http response body (crosscheck): "+ httpResponseStr2);
        
        // check result
        if (httpResponseStr2.contains(SUCCESS_STR)) {
            fail("crosscheck failed");
        }
    }
    @Ignore(value="this service is not always on")
    @Test(timeout=15000)
    @Given("#initializeTor")
    public void testThatRequestGoesThroughTorNetwork2() throws Exception  {
        testThatRequestGoesThroughTorNetwork();
    }    
  
    @Test(timeout=15000)
    @Given("#initializeTor")
    public void testThatRequestGoesThroughTorNetworkVariantB() throws Exception  {
        final String TORCHECK_HOSTNAME = "check.torproject.org";
        final TcpipNetAddress TORCHECK_NETADDRESS = new TcpipNetAddress(TORCHECK_HOSTNAME, 80);
        
        // create connection
        NetSocket topSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR_OVER_TLS_OVER_TCPIP).
            createNetSocket(null, null, TORCHECK_NETADDRESS);

        // communicate with the remote side
        byte[] httpResponse = HttpUtil.getInstance().get(
                topSocket, TORCHECK_NETADDRESS, "/", 5000);
        String httpResponseStr = ByteArrayUtil.showAsString(httpResponse);
        log.info("http response body: "+ httpResponseStr);
        
        // make the httpResponseStr readable in HTML reports
        httpResponseStr = removeHtmlTags(httpResponseStr);
        
        // trivial check
        final int MIN_RESONSE_LEN = 100;
        if (httpResponseStr==null || httpResponseStr.length()<MIN_RESONSE_LEN) {
            fail("invalid/short HTTP response body="+httpResponseStr);
        }
        
        // check result
        final String SUCCESS_STR = "Congratulations. Your browser is configured to use Tor.";
        if (!httpResponseStr.contains(SUCCESS_STR)) {
            fail("the request did NOT go through Tor network, response body="+httpResponseStr);
        }

        ///////////////////////////////////////////////////
        // crosscheck
        ///////////////////////////////////////////////////

        // create connection
        NetSocket topSocket2 =  NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP).
            createNetSocket(null, null, TORCHECK_NETADDRESS);

        // communicate with the remote side
        byte[] httpResponse2 = HttpUtil.getInstance().get(
                topSocket2, TORCHECK_NETADDRESS, "/", 5000);
        String httpResponseStr2 = ByteArrayUtil.showAsString(httpResponse2);
        log.info("http response body (crosscheck): "+ httpResponseStr2);
        
        // check result
        if (httpResponseStr2.contains(SUCCESS_STR)) {
            fail("crosscheck failed");
        }
    }
    @Test(timeout=15000)
    @Given("#initializeTor")
    public void testThatRequestGoesThroughTorNetworkVariantB2() throws Exception  {
        testThatRequestGoesThroughTorNetworkVariantB();
    }    

    
    @Test(timeout=5000)
    @Given("#initializeTor")
    public void testGetValidTorRouters() throws Exception  {
        // call API method
        Collection<Router> routers = torNetLayer.getValidTorRouters();

        // check result
        final int MIN_NUM_OF_ROUTERS = 10;
        if (routers==null || routers.size()<MIN_NUM_OF_ROUTERS) {
            fail("invalid result of torNetLayer.getValidTorRouters()="+routers);
        }
        
        // show one router
        log.info("one router="+routers.iterator().next());
    }
}
