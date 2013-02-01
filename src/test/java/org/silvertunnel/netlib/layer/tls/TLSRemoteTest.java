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
package org.silvertunnel.netlib.layer.tls;

import static org.junit.Assert.fail;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Before;
import org.junit.Test;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.layer.logger.LoggingNetLayer;
import org.silvertunnel.netlib.layer.tcpip.TcpipNetLayer;
import org.silvertunnel.netlib.util.ByteArrayUtil;


public class TLSRemoteTest {
    private static final Logger log = Logger.getLogger(TLSRemoteTest.class.getName());

    public static final String WEBPAGE_GMX_NET_CONTENT_SNIPPET = "<title>GMX - E-Mail, FreeMail, De-Mail, Themen-";
    
    @Before
    public void setUp() throws Exception {
        // create lower layer
        NetLayer tcpipNetLayer = new TcpipNetLayer();
        NetLayer loggingTcpipNetLayer = new LoggingNetLayer(tcpipNetLayer, "upper tcpip  ");
        NetFactory.getInstance().registerNetLayer(NetLayerIDs.TCPIP, loggingTcpipNetLayer);
        
        // create TLS/SSL layer
        TLSNetLayer tlsNetLayer = new TLSNetLayer(loggingTcpipNetLayer);
        NetLayer loggingTlsNetLayer = new LoggingNetLayer(tlsNetLayer, "upper tls/ssl");
        NetFactory.getInstance().registerNetLayer(NetLayerIDs.TLS_OVER_TCPIP, loggingTlsNetLayer);
        
        log.info("------------------------------------------------------------------------------------------------");
    }
    
    @Test
    public void test_http_request() throws Exception {
        // create connection
        NetSocket tcpipSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP).createNetSocket(null, null, new TcpipNetAddress("www.gmx.net", 80));
        completeHttpRequestResponse(tcpipSocket);
    }

    @Test
    public void test_https_request() throws Exception {
        // create connection
        NetSocket tlsSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TLS_OVER_TCPIP).createNetSocket(null, null, new TcpipNetAddress("www.gmx.net", 443));
        completeHttpRequestResponse(tlsSocket);
    }

    @Test
    public void test_https_request_withLimitedCiphers() throws Exception {
        // create connection
        Map<String,Object> props = new HashMap<String,Object>();
        props.put(TLSNetLayer.ENABLES_CIPHER_SUITES, "TLS_RSA_WITH_AES_128_CBC_SHA");
        NetSocket tlsSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TLS_OVER_TCPIP).createNetSocket(props, null, new TcpipNetAddress("www.gmx.net", 443));
        completeHttpRequestResponse(tlsSocket);
    }

    @Test
    public void test_https_request_withInvalidCiphers() throws Exception {
        // create connection
        Map<String,Object> props = new HashMap<String,Object>();
        props.put(TLSNetLayer.ENABLES_CIPHER_SUITES, "MICH_GIBTS_NICHT");
        try {
            NetSocket tlsSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TLS_OVER_TCPIP).createNetSocket(props, null, new TcpipNetAddress("www.gmx.net", 443));
            completeHttpRequestResponse(tlsSocket);
            fail("expected exception not thrown");
        } catch (Exception e) {
            log.info("expected exception catched: "+e);
        }
    }


    ///////////////////////////////////////////////////////
    // helper methods
    ///////////////////////////////////////////////////////
    
    private void completeHttpRequestResponse(NetSocket netSocket) throws Exception {
        // write data
        String dataToSend = "GET / HTTP/1.1\nHost: www.gmx.net\n\n";
        netSocket.getOutputStream().write(dataToSend.getBytes());
        netSocket.getOutputStream().flush();
        
        // read (result) data
        int MAX_BUFFER_SIZE = 100000;
        InputStream is = netSocket.getInputStream();
        byte[] resultBuffer = ByteArrayUtil.readDataFromInputStream(MAX_BUFFER_SIZE, is);
        if (resultBuffer.length>=MAX_BUFFER_SIZE) {
            log.info("result buffer is full");
        } else {
            log.info("end of result stream");
        }
        String result = new String(resultBuffer);
        
        // close connection
        netSocket.close();
        
        // show and check result data
        log.fine("result=\""+result+"\"");
        if (!result.contains(WEBPAGE_GMX_NET_CONTENT_SNIPPET)) {
            fail("wrong result=\""+result+"\"");
        }
    }
}
