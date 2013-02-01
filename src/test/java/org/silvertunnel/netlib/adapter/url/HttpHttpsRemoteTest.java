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

package org.silvertunnel.netlib.adapter.url;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.layer.logger.LoggingNetLayer;
import org.silvertunnel.netlib.layer.tcpip.TcpipNetLayer;
import org.silvertunnel.netlib.layer.tls.TLSNetLayer;
import org.silvertunnel.netlib.layer.tls.TLSRemoteTest;
import org.silvertunnel.netlib.util.ByteArrayUtil;


public class HttpHttpsRemoteTest {
    private static final Logger log = Logger.getLogger(HttpHttpsRemoteTest.class.getName());

    private LoggingNetLayer loggingTcpipNetLayer;
    private LoggingNetLayer loggingTlsNetLayer;
    
    /**
     * Initialize the URLStreamHandlerFactory.
     * 
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        // enable redirection
        URLGlobalUtil.initURLStreamHandlerFactory();

        // create lower layer (TCP/IP)
        NetLayer tcpipNetLayer = new TcpipNetLayer();
        loggingTcpipNetLayer   = new LoggingNetLayer(tcpipNetLayer, "upper tcpip  ");

        // create lower layer (TLS)
        NetLayer tcpipNetLayer2 = new TcpipNetLayer();
        NetLayer loggingTcpipNetLayer2   = new LoggingNetLayer(tcpipNetLayer2, "upper tcpip(tls)  ");
        NetLayer tlsNetLayer   = new TLSNetLayer(loggingTcpipNetLayer2);
        loggingTlsNetLayer     = new LoggingNetLayer(tlsNetLayer, "upper tls  ");
        

        // select the NetSocket implementation
        URLGlobalUtil.setNetLayerUsedByURLStreamHandlerFactory(loggingTcpipNetLayer, loggingTlsNetLayer);
        log.info("------------------------------------------------------------------------------------------------");
    }
    
    /**
     * After test execution: Let the URLStreamHandlerFactory behave as normal as possible.
     * 
     * @throws Exception
     */
    @After
    public void tearDown() throws Exception {
        // select the NetSocket implementation
        NetLayer tcpipNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP); 
        NetLayer tlsNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TLS_OVER_TCPIP); 
        URLGlobalUtil.setNetLayerUsedByURLStreamHandlerFactory(tcpipNetLayer, tlsNetLayer);
    }
    
    @Test(timeout=100009999)
    public void test_http() throws Exception {
        // action
        long connectionCountStart = loggingTcpipNetLayer.getConnectionEstablisedCounter();
        String urlStr = "http://www.gmx.net/";
        URL url = new URL(urlStr);
        URLConnection urlConnection = url.openConnection();
        
        // receive and check HTTP response
        InputStream responseIs = urlConnection.getInputStream();
        checkResponse(responseIs);
        long connectionCount = loggingTcpipNetLayer.getConnectionEstablisedCounter() - connectionCountStart;
        assertEquals("wrong number of established connections (via logging layer) during test", 1, connectionCount);
    }

    @Test(timeout=10000)
    @Ignore(value="only used for manual tests")
    public void test_client_http_headers() throws Exception {
        // action
        long connectionCountStart = loggingTcpipNetLayer.getConnectionEstablisedCounter();
        String urlStr = "http://www.xhaus.com/headers";
        URL url = new URL(urlStr);
        URLConnection urlConnection = url.openConnection();
        
        // receive and check HTTP response
        InputStream responseIs = urlConnection.getInputStream();
        checkResponse(responseIs);
        long connectionCount = loggingTcpipNetLayer.getConnectionEstablisedCounter() - connectionCountStart;
        assertEquals("wrong number of established connections (via logging layer) during test", 1, connectionCount);
    }

    @Test(timeout=10000)
    public void test_https() throws Exception {
        // action
        long connectionCountStart = loggingTlsNetLayer.getConnectionEstablisedCounter();
        String urlStr = "https://www.gmx.net/";
        URL url = new URL(urlStr);
        URLConnection urlConnection = url.openConnection();
        
        // receive and check HTTP response
        InputStream responseIs = urlConnection.getInputStream();
        checkResponse(responseIs);
        long connectionCount = loggingTlsNetLayer.getConnectionEstablisedCounter() - connectionCountStart;
        assertEquals("wrong number of established connections (via logging layer) during test", 1, connectionCount);
    }

    @Test(timeout=10000)
    public void test_http2() throws Exception {
        test_http();
    }
        
    ///////////////////////////////////////////////////////
    // helper methods
    ///////////////////////////////////////////////////////
    
    private void checkResponse(InputStream is) throws Exception {
        // read result/response data
        int MAX_BUFFER_SIZE = 100000;
        byte[] resultBuffer = ByteArrayUtil.readDataFromInputStream(MAX_BUFFER_SIZE, is);
        if (resultBuffer.length>=MAX_BUFFER_SIZE) {
            log.info("result buffer is full");
        } else {
            log.info("end of result stream");
        }
        String result = new String(resultBuffer);
        
        // show and check result data
        log.fine("result=\""+result+"\"");
        if (!result.contains(TLSRemoteTest.WEBPAGE_GMX_NET_CONTENT_SNIPPET)) {
            fail("wrong result=\""+result+"\"");
        }
    }
}
