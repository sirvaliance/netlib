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

import java.util.Arrays;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.silvertunnel.netlib.api.ByteArrayTestUtil;
import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.TestUtil;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.layer.logger.LoggingNetLayer;
import org.silvertunnel.netlib.layer.mock.MockNetLayer;
import org.silvertunnel.netlib.layer.tcpip.TcpipNetLayer;
import org.silvertunnel.netlib.util.ByteArrayUtil;

@RunWith(Parameterized.class)
public class NetProxyLocalTest {
    private static final Logger log = Logger.getLogger(NetProxyLocalTest.class.getName());

    private byte[] USER_DATA_REQUEST;
    private byte[] USER_DATA_RESPONSE;
    
    private MockNetLayer mockNetLayer;
    private Thread netlibProxyThread;
    private static final int PROXY_SERVER_PORT = 11080;
    
    private static final String MOCK = "mock";

    /** if NUM_OF_TEST_EXECUTIONS==1 then this test class behaves like an unparameterized one */
    private static int NUM_OF_TEST_EXECUTIONS = 1;
    
    @Parameters
    public static Collection<Object[]> multipleTestExecutions() {
        return Arrays.asList(new Object[NUM_OF_TEST_EXECUTIONS][0]);
    }
    
    public NetProxyLocalTest() {
        try {
            USER_DATA_REQUEST = ByteArrayUtil.getByteArray("<request>Das ist mein Request", 2222, "</request>");
            USER_DATA_RESPONSE = ByteArrayUtil.getByteArray("<response>Hier ist\n\nmeine Antwort\n fuer heute", 3333, "</response>");
            
        } catch (Exception e) {
            log.log(Level.SEVERE, "unexpected during construction", e);
        }
    }

    @Before
    public void setUp() throws Exception {
        // create layer that will always be used by the proxy for connection connect to the proxy client 
        NetLayer tcpipNetLayer = new TcpipNetLayer();
        NetFactory.getInstance().registerNetLayer(NetLayerIDs.TCPIP, tcpipNetLayer);
        
        // create layer that will be used to connect the proxy to
        final long WAIT_ENDLESS = -1;
        mockNetLayer = new MockNetLayer(USER_DATA_RESPONSE, false, WAIT_ENDLESS);
        NetLayer loggingMockNetLayer = new LoggingNetLayer(mockNetLayer, "mock");
        NetFactory.getInstance().registerNetLayer(MOCK, loggingMockNetLayer);
    }
    
    @Test(timeout=3000)
    public void testWithMock() throws Exception {
        // start and proxy
        netlibProxyThread = new Thread("NetProxy-main") {
            public void run() {
                String[] commanLineArgs = {"127.0.0.1:"+PROXY_SERVER_PORT, MOCK};
                NetlibProxy.start(commanLineArgs);
            }
        };
        netlibProxyThread.start();
        
        // wait until proxy startup is finished
        while (!NetlibProxy.isStarted()) {
            // wait a bit
            Thread.sleep(1000);
        }
        
        // connect to the proxy
        log.info("connect to the proxy");
        NetAddress proxyAddress = new TcpipNetAddress("localhost", PROXY_SERVER_PORT);
        NetSocket socket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP).createNetSocket(null, null, proxyAddress);

        // send user data to remote side
        log.info("send user data to remote side, i.e. to the mock");
        socket.getOutputStream().write(USER_DATA_REQUEST);
        socket.getOutputStream().flush();

        // receive and check user data from remote side
        log.info("receive and check user data from remote side, i.e. from the mock");
        ByteArrayTestUtil.assertByteArrayFromInputStream(null, "wrong user data response", USER_DATA_RESPONSE, socket.getInputStream()); 
        
        // check user data received by the remote side (mock)
        log.info("check user data received by the remote side (mock)");
        TestUtil.waitUntilMinimumNumberOfReceivedBytes(mockNetLayer.getFirstSessionHistory(), USER_DATA_REQUEST.length);
        socket.close();
        NetAddress expectedNetAddress = null;
        TestUtil.assertMockNetLayerSavedData("wrong data received by mock", mockNetLayer.getFirstSessionHistory(), USER_DATA_REQUEST, expectedNetAddress);
    }
    
    @After
    public void tearDown() throws Exception {
        NetlibProxy.stop();
        netlibProxyThread.join();
    }
}
