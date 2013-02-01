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

import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.silvertunnel.netlib.api.ByteArrayTestUtil;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.layer.mock.MockNetLayer;
import org.silvertunnel.netlib.util.ByteArrayUtil;
import org.silvertunnel.netlib.util.HttpUtil;

/**
 * Test ForwardingNetLayer.
 * 
 * In detail: test forward over a forward  over mock.
 * 
 * @author hapke
 */
public class NetlibURLStreamHandlerLocalTest {
    private static final Logger log = Logger.getLogger(NetlibURLStreamHandlerLocalTest.class.getName());

    private byte[] USER_DATA_TCP_RESPONSE;
    private byte[] EXPECTED_USER_DATA_HTTPCONTENT_RESPONSE;
    
    public NetlibURLStreamHandlerLocalTest() {
        try {
            USER_DATA_TCP_RESPONSE = ByteArrayUtil.getByteArray(
                    "HTTP/1.0 200 OK\nContent-Language: de\nContent-Type: text/html; charset=utf-8\n\n"+
                    "Hier ist\n\nmeine Antwort\n fuer heute", 3000, "\u00e0.");
            EXPECTED_USER_DATA_HTTPCONTENT_RESPONSE = ByteArrayUtil.getByteArray(
                    "Hier ist\n\nmeine Antwort\n fuer heute", 3000, "\u00e0.");
            
        } catch (Exception e) {
            log.log(Level.SEVERE, "unexpected during construction", e);
        }
    }

    /**
     * Initialize the URLStreamHandlerFactory.
     * 
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        // enable redirection
        URLGlobalUtil.initURLStreamHandlerFactory();

        // select the NetSocket implementation
        final long WAIT_ENDLESS = -1;
        NetLayer tcpipNetLayer = new MockNetLayer(USER_DATA_TCP_RESPONSE, false, WAIT_ENDLESS);
        NetLayer noTlsNetLayer = null;
        URLGlobalUtil.setNetLayerUsedByURLStreamHandlerFactory(tcpipNetLayer, noTlsNetLayer);
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
    
    @Test(timeout=2000)
    public void testReceivingData() throws Exception {
        // action
        String urlStr = "http://"+HttpUtil.HTTPTEST_SERVER_NETADDRESS.getHostname()+"/httptest/smalltest.jsp?id=NetlibURLStreamHandlerLocalTest";
        URL url = new URL(urlStr);
        URLConnection urlConnection = url.openConnection();
        
        // receive and check HTTP response
        InputStream is = urlConnection.getInputStream();
        ByteArrayTestUtil.assertByteArrayFromInputStream(null, "wrong user data response", EXPECTED_USER_DATA_HTTPCONTENT_RESPONSE, is); 
        is.close();
    }
}
