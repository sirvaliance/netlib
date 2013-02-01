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

package org.silvertunnel.netlib.tool;

import static org.junit.Assert.assertEquals;

import java.net.URL;
import java.util.Map;
import java.util.logging.Logger;

import org.junit.Test;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.tool.SimpleHttpClient;
import org.silvertunnel.netlib.util.HttpUtil;

/**
 * Test of class HttpClient.
 * 
 * @author hapke
 */
public class SimpleHttpClientRemoteTest {
    private static final Logger log = Logger.getLogger(SimpleHttpClientRemoteTest.class.getName());

    private static final String UTF8 = "UTF-8";
    
    private static final String POSTTEST_URL = "http://silvertunnel.org/httptest/posttest.jsp";
    private static final String POSTTEST_URL2 = "http://109.123.119.163:9031/tor/rendezvous2/publish";
       
    @Test(timeout=15000)
    public void testGetRequest() throws Exception {
        // generate the id
        int randomNo = (int)(1000000000*Math.random());
        String id = "testGetRequest"+randomNo;
        
        // communicate with the remote side
        NetLayer netLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP);
        String path = "/httptest/smalltest.jsp?id="+id;
        String httpResponse = SimpleHttpClient.getInstance().get(netLayer, HttpUtil.HTTPTEST_SERVER_NETADDRESS, path);
        
        // check response
        String expectedResponse = "<response><id>"+id+"</id></response>\n";
        assertEquals("wrong response", expectedResponse, httpResponse);
    }
    
    
    @Test(timeout=15000)
    public void testPostRequest() throws Exception {
        final String DATA_TO_POST = "Das sind die\nPost\nDaten";
        final String EXPECTED_RESPONSE = "<postedData>"+DATA_TO_POST+"</postedData>";
        final long TIMEOUT_MS = 3000;
        
        // prepare request
        URL url = new URL(POSTTEST_URL);
        NetLayer netLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP);
        int port = url.getPort();
        TcpipNetAddress httpServerNetAddress = new TcpipNetAddress(url.getHost(), port<0 ? 80 : port);
        Map<String,Object> localProperties = null;
        String pathOnHttpServer = url.getPath();
        if (pathOnHttpServer==null || pathOnHttpServer.length()<1) {
            pathOnHttpServer = "/";
        }
        log.info("pathOnHttpServer="+pathOnHttpServer);

        // execute request and check response
        NetSocket netSocket = netLayer.createNetSocket(localProperties, /*localAddress*/ null, httpServerNetAddress);
        String response = new String(HttpUtil.getInstance().post(netSocket, httpServerNetAddress, pathOnHttpServer, DATA_TO_POST.getBytes(UTF8), TIMEOUT_MS), UTF8);
        if (!response.contains(EXPECTED_RESPONSE)) {
            assertEquals("wrong result",
                    EXPECTED_RESPONSE,
                    response);
        }
    }
}
