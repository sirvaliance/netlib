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
package org.silvertunnel.netlib.adapter.socket;

import static org.junit.Assert.fail;
import static org.silvertunnel.netlib.util.HttpUtil.HTTPTEST_SERVER_NETADDRESS;

import java.net.InetSocketAddress;
import java.util.logging.Logger;

import org.junit.BeforeClass;
import org.junit.Test;
import org.silvertunnel.netlib.api.ByteArrayTestUtil;
import org.silvertunnel.netlib.api.HttpTestUtil;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.layer.mock.MockNetLayer;
import org.silvertunnel.netlib.util.ByteArrayUtil;
import org.silvertunnel.netlib.util.HttpUtil;

/**
 * Test to test SocketUtil.initSocketImplFactory() and SocketUtil.setNetLayerUsedBySocketImplFactory()
 * 
 * @author hapke
 */
public class SocketAdapterRemoteTest {
    private static final Logger log = Logger.getLogger(SocketAdapterRemoteTest.class.getName());

    private static final int TIMEOUT_IN_MS = 2000;
    
    @BeforeClass
    public static void setUp() throws Exception {
        // initialize socket adapter logic
        SocketGlobalUtil.initSocketImplFactory();
    }

    @Test
    public void test_Socket_using_SocketImpl_with_TcpipNetLayer() throws Exception {
        // select NetLayer
        NetLayer netLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP); 
        SocketGlobalUtil.setNetLayerUsedBySocketImplFactory(netLayer);
        
        // prepare connection
        ExtendedSocket socket = new ExtendedSocket(HttpUtil.HTTPTEST_SERVER_NAME, HttpUtil.HTTPTEST_SERVER_PORT);
        
        // use open socket to execute HTTP request and to check the response
        HttpTestUtil.executeSmallTest(socket, "test_Socket_using_SocketImpl_with_TcpipNetLayer", TIMEOUT_IN_MS);
    }

    @Test
    public void test_Socket_using_InvalidSocketImpl() throws Exception {
        // select NetLayer: select InvalidSocketImpl
        SocketGlobalUtil.setNetLayerUsedBySocketImplFactory(null);
        
        try {
            // create connection
            ExtendedSocket socket = new ExtendedSocket(HttpUtil.HTTPTEST_SERVER_NAME, HttpUtil.HTTPTEST_SERVER_PORT);
            
            // use open socket to execute HTTP request and to check the response
            HttpTestUtil.executeSmallTest(socket, "test_Socket_using_InvalidSocketImpl", TIMEOUT_IN_MS);
            
            fail("expected UnsupportedOperationException not thrown");
            
        } catch (UnsupportedOperationException e) {
            log.info("expected exception was thrown (i.e. everything is fine): "+e);
        }
    }

    /**
     * Verify that TcpipNetSocket/TcpipNetLayer bypasses the SocketImpl used by class Socket.
     * 
     * @throws Exception
     */
    @Test
    public void test_TcpipNetSocket_while_Socket_uses_InvalidSocketImpl() throws Exception {
        // select NetLayer: select InvalidSocketImpl
        SocketGlobalUtil.setNetLayerUsedBySocketImplFactory(null);
        
        // prepare connection
        NetSocket topSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP).
                createNetSocket(null, null, HTTPTEST_SERVER_NETADDRESS);

        // use open socket to execute HTTP request and to check the response
        org.silvertunnel.netlib.api.HttpTestUtil.executeSmallTest(
                topSocket, "test_TcpipNetSocket_while_Socket_uses_InvalidSocketImpl", TIMEOUT_IN_MS);
    }
    
    @Test
    public void test_Socket_using_SocketImpl_with_MockNetLayer() throws Exception {
        // select NetLayer
        final String expectedResponseBodyStr = "this is a\nresponse\nfrom\nthe\nMockNetLayer";
        final byte[] expectedResponseBody  = expectedResponseBodyStr.getBytes("UTF-8");
        final String expectedResponseStr = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n"+expectedResponseBodyStr;
        final byte[] expectedResponse = expectedResponseStr.getBytes("UTF-8");
        final boolean allowMultipleSessions = false;
        final long WAIT_ENDLESS = -1;
        MockNetLayer mockNetLayer = new MockNetLayer(expectedResponse, allowMultipleSessions, WAIT_ENDLESS);
        SocketGlobalUtil.setNetLayerUsedBySocketImplFactory(mockNetLayer);
        
        // prepare connection
        ExtendedSocket socket = new ExtendedSocket(HttpUtil.HTTPTEST_SERVER_NAME, HttpUtil.HTTPTEST_SERVER_PORT);
        
        // use open socket to execute HTTP request and to check the response
        byte[] httpResponseBody = HttpUtil.getInstance().get(
                socket,
                HTTPTEST_SERVER_NETADDRESS,
                "/httptest/smalltest.jsp?id=test_Socket_using_SocketImpl_with_MockNetLayer",
                TIMEOUT_IN_MS);
        
        // check response
        log.info("http response body: "+ByteArrayUtil.showAsString(httpResponseBody));
        ByteArrayTestUtil.assertEquals("wrong http response", expectedResponseBody, httpResponseBody); 
        
        socket.close();
    }
    
    @Test
    public void test_OriginalSocketImpl() throws Exception {
        // select NetLayer: select InvalidSocketImpl
        SocketGlobalUtil.setNetLayerUsedBySocketImplFactory(null);

        // prepare connection
        ExtendedSocket socket = SocketGlobalUtil.createOriginalSocket();
        socket.connect(new InetSocketAddress(HttpUtil.HTTPTEST_SERVER_NAME, HttpUtil.HTTPTEST_SERVER_PORT));
        
        // use open socket to execute HTTP request and to check the response
        HttpTestUtil.executeSmallTest(socket, "test_OriginalSocketImpl", TIMEOUT_IN_MS);
    }

    /**
     * The same as test_Socket_using_SocketImpl_with_TcpipNetLayer().
     * Just do it again to see that the other test cases did not break the environment.
     * 
     * @throws Exception
     */
    @Test
    public void test_Socket_using_SocketImpl_with_TcpipNetLayer_again() throws Exception {
        // select NetLayer
        NetLayer netLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP); 
        SocketGlobalUtil.setNetLayerUsedBySocketImplFactory(netLayer);
        
        // prepare connection
        ExtendedSocket socket = new ExtendedSocket(HttpUtil.HTTPTEST_SERVER_NAME, HttpUtil.HTTPTEST_SERVER_PORT);
        
        // use open socket to execute HTTP request and to check the response
        HttpTestUtil.executeSmallTest(socket, "test_Socket_using_SocketImpl_with_TcpipNetLayer_again", TIMEOUT_IN_MS);
    }
}
