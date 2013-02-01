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
package org.silvertunnel.netlib.layer.tcpip;

import static org.junit.Assert.assertEquals;
import static org.silvertunnel.netlib.util.HttpUtil.HTTPTEST_SERVER_NETADDRESS;

import java.net.Socket;
import java.util.logging.Logger;

import org.junit.Before;
import org.junit.Test;
import org.silvertunnel.netlib.api.ApiClientLocalTest;
import org.silvertunnel.netlib.api.HttpTestUtil;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.impl.NetSocket2Socket;
import org.silvertunnel.netlib.layer.modification.AddModificator;
import org.silvertunnel.netlib.layer.modification.ModificatorNetLayer;
import org.silvertunnel.netlib.util.HttpUtil;

public class ApiClientRemoteTest {
    private static final Logger log = Logger.getLogger(ApiClientLocalTest.class.getName());

    private static final String NET_LAYER_ID2 = "modify_over_tcpip";

    @Before
    public void setUp() throws Exception {
        // create layer for modify_over_tcpip
        NetLayer tcpipNetLayer = new TcpipNetLayer();
        NetLayer modificatorLayer2 = new ModificatorNetLayer(tcpipNetLayer, new AddModificator(1-1), new AddModificator(0));
        NetFactory.getInstance().registerNetLayer(NET_LAYER_ID2, modificatorLayer2);
    }
    
    @Test(timeout=15000)
    public void testLayer_modify_over_tcpip_with_old_socket() throws Exception {
        // create connection
        NetSocket topSocket = NetFactory.getInstance().getNetLayerById(NET_LAYER_ID2).
        		createNetSocket(null, null, HttpUtil.HTTPTEST_SERVER_NETADDRESS);
        Socket top = new NetSocket2Socket(topSocket);
        
        // write data
        String dataToSend = "GET /httptest/smalltest.jsp?id=APIHelloWorld\n\n";
        top.getOutputStream().write(dataToSend.getBytes());
        top.getOutputStream().flush();
        
        // read (result) data
        byte[] resultBuffer = new byte[10000];
        int len = top.getInputStream().read(resultBuffer);
        String result = new String(resultBuffer).substring(0, len);
        
        // close connection
        top.close();
        
        // show and check result data
        log.info("result=\""+result+"\"");
        assertEquals("got wrong result",
                "<response><id>APIHelloWorld</id></response>\n",
                result);
    }
    

    @Test(timeout=15000)
    public void testLayer_modify_over_tcpip() throws Exception {
        // create connection
        NetSocket topSocket = NetFactory.getInstance().getNetLayerById(NET_LAYER_ID2).
        		createNetSocket(null, null, HTTPTEST_SERVER_NETADDRESS);
        
        // use open socket to execute HTTP request and to check the response
        HttpTestUtil.executeSmallTest(topSocket, "testLayerModifyOverTcpip", 2000);
    }
}
