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

import java.util.logging.Logger;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.util.ByteArrayUtil;
import org.silvertunnel.netlib.util.HttpUtil;

import ch.unibe.jexample.Given;
import ch.unibe.jexample.JExample;


/**
 * Test Tor's hidden services (client implementation).
 * 
 * @author hapke
 */
//Problem because @Timeout was ignored: @RunWith(JExample.class)
public class TorHiddenServiceClientRemoteTest extends TorRemoteAbstractTest {
    private static final Logger log = Logger.getLogger(TorHiddenServiceClientRemoteTest.class.getName());
    
    @Test(timeout=600000)
    public void initializeTor() throws Exception {
        // repeat method declaration here to be the first test method of the class
        super.initializeTor();
    }
        
    //@Ignore
    @Test(timeout=120000)
    @Given("#initializeTor")
    public void testAccessToTorsExampleOnionDomain() throws Exception {
        super.initializeTor();
        
        final String TORCHECK_HOSTNAME = "duskgytldkxiuqc6.onion";
        final TcpipNetAddress TORCHECK_NETADDRESS = new TcpipNetAddress(TORCHECK_HOSTNAME, 80);
        
        // create connection
        NetSocket topSocket = null;
        try {
            topSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR_OVER_TLS_OVER_TCPIP).
                createNetSocket(null, null, TORCHECK_NETADDRESS);
    
            // communicate with the remote side
            byte[] httpResponse = HttpUtil.getInstance().get(
                    topSocket, TORCHECK_NETADDRESS, "/", 10000);
            String httpResponseStr = ByteArrayUtil.showAsString(httpResponse);
            log.info("http response body: "+ httpResponseStr);
            
            // make the httpResponseStr readable in HTML reports
            httpResponseStr = removeHtmlTags(httpResponseStr);
    
            // check result
            final String SUCCESS_STR = "This is the example page for Tor's";
            if (!httpResponseStr.contains(SUCCESS_STR)) {
                fail("did not get correct response of hidden service, response body="+httpResponseStr);
            }
        } finally {
            if (topSocket!=null) {
                topSocket.close();
            }
        }
    }
    //@Ignore
    @Test(timeout=120000)
    @Given("#initializeTor")
    public void testAccessToTorsExampleOnionDomain2() throws Exception {
        testAccessToTorsExampleOnionDomain();
    }

    @Ignore(value="this service is not always on")
    @Test(timeout=120000)
    @Given("#initializeTor")
    public void testAccessToWikileaksOnionDomain() throws Exception {
        super.initializeTor();

        final String TORCHECK_HOSTNAME = "gaddbiwdftapglkq.onion";
        final TcpipNetAddress TORCHECK_NETADDRESS = new TcpipNetAddress(TORCHECK_HOSTNAME, 80);
        
        // create connection
        NetSocket topSocket = null;
        try {
            topSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR_OVER_TLS_OVER_TCPIP).
                createNetSocket(null, null, TORCHECK_NETADDRESS);
    
            // communicate with the remote side
            byte[] httpResponse = HttpUtil.getInstance().get(
                    topSocket, TORCHECK_NETADDRESS, "/", 10000);
            String httpResponseStr = ByteArrayUtil.showAsString(httpResponse);
            log.info("http response body: "+ httpResponseStr);
            
            // make the httpResponseStr readable in HTML reports
            httpResponseStr = removeHtmlTags(httpResponseStr);
    
            // check result
            final String SUCCESS_STR = "Click here to make a secure submission";
            if (!httpResponseStr.contains(SUCCESS_STR)) {
                fail("did not get correct response of hidden service, response body="+httpResponseStr);
            }
        } finally {
            if (topSocket!=null) {
                topSocket.close();
            }
        }
    }

    @Ignore(value="this service is not always on")
    @Test(timeout=120000)
    @Given("#initializeTor")
    public void testAccessToTORDirectoryOnionDomain() throws Exception {
        super.initializeTor();
        final String TORCHECK_HOSTNAME = "dppmfxaacucguzpc.onion";
        final TcpipNetAddress TORCHECK_NETADDRESS = new TcpipNetAddress(TORCHECK_HOSTNAME, 80);
        
        // create connection
        NetSocket topSocket = null;
        try {
            topSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR_OVER_TLS_OVER_TCPIP).
                createNetSocket(null, null, TORCHECK_NETADDRESS);
    
            // communicate with the remote side
            byte[] httpResponse = HttpUtil.getInstance().get(
                    topSocket, TORCHECK_NETADDRESS, "/", 10000);
            String httpResponseStr = ByteArrayUtil.showAsString(httpResponse);
            log.info("http response body: "+ httpResponseStr);
            
            // make the httpResponseStr readable in HTML reports
            httpResponseStr = removeHtmlTags(httpResponseStr);
    
            // check result
            final String SUCCESS_STR = "The link directory for TOR";
            if (!httpResponseStr.contains(SUCCESS_STR)) {
                fail("did not get correct response of hidden service, response body="+httpResponseStr);
            }
        } finally {
            if (topSocket!=null) {
                topSocket.close();
            }
        }
    }

    @Ignore(value="this service is just a test service and only temporarily available")
    @Test(timeout=120000)
    @Given("#initializeTor")
    public void testAccessToSTHiddenServiceOnionDomain() throws Exception {
        super.initializeTor();
        final String TORCHECK_HOSTNAME = "4xuwatxuqzfnqjuz.onion";
        final TcpipNetAddress TORCHECK_NETADDRESS = new TcpipNetAddress(TORCHECK_HOSTNAME, 80);
        
        // create connection
        NetSocket topSocket = null;
        try {
            topSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR_OVER_TLS_OVER_TCPIP).
                createNetSocket(null, null, TORCHECK_NETADDRESS);
    
            // communicate with the remote side
            byte[] httpResponse = HttpUtil.getInstance().get(
                    topSocket, TORCHECK_NETADDRESS, "/", 10000);
            String httpResponseStr = ByteArrayUtil.showAsString(httpResponse);
            log.info("http response body: "+ httpResponseStr);
            
            // make the httpResponseStr readable in HTML reports
            httpResponseStr = removeHtmlTags(httpResponseStr);
    
            // check result
            final String SUCCESS_STR = "Speziell f&uuml;r kleine und mittlere Unternehmen sowie f&uuml;r Privatpersonen";
            if (!httpResponseStr.contains(SUCCESS_STR)) {
                fail("did not get correct response of hidden service, response body="+httpResponseStr);
            }
        } finally {
            if (topSocket!=null) {
                topSocket.close();
            }
        }
   }
}
