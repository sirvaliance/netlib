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
package org.silvertunnel.netlib.api;

import static org.junit.Assert.assertEquals;

import java.util.logging.Logger;

import org.junit.Before;
import org.junit.Test;
import org.silvertunnel.netlib.layer.buffered.BufferedNetLayer;
import org.silvertunnel.netlib.layer.echo.EchoNetLayer;
import org.silvertunnel.netlib.layer.modification.AddModificator;
import org.silvertunnel.netlib.layer.modification.ModificatorNetLayer;

public class ApiClientLocalTest {
    private static final Logger log = Logger.getLogger(ApiClientLocalTest.class.getName());

    private static final String NET_LAYER_ID1 = "2modify_over_echo";

    @Before
    public void setUp() throws Exception {
        // create layer for modify_over_echo
        NetLayer echoNetLayer = new EchoNetLayer();
        NetLayer modificatorLayer = new ModificatorNetLayer(echoNetLayer, new AddModificator(1), new AddModificator(3));
        NetLayer bufferedNetLayer = new BufferedNetLayer(modificatorLayer);
        NetLayer modificatorLayer1a = new ModificatorNetLayer(bufferedNetLayer, new AddModificator(-3), new AddModificator(3-3));
        NetFactory.getInstance().registerNetLayer(NET_LAYER_ID1, modificatorLayer1a);
    }
    
    @Test
    public void testLayer_modify_over_echo() throws Exception {
        // create connection
        NetSocket topSocket = NetFactory.getInstance().getNetLayerById(NET_LAYER_ID1).
        		createNetSocket(null, (NetAddress)null, (NetAddress)null);
        
        // write data
        String dataToSend = "hello1 world sent data";
        topSocket.getOutputStream().write(dataToSend.getBytes());
        topSocket.getOutputStream().flush();
        
        // read (result) data
        byte[] resultBuffer = new byte[10000];
        int len = topSocket.getInputStream().read(resultBuffer);
        String result = new String(resultBuffer).substring(0, len);
        
        // close connection
        topSocket.close();
        
        // show and check result data
        log.info("result=\""+result+"\"");
        assertEquals("got wrong result",
                "ifmmp2!xpsme!tfou!ebub",
                result);
    }
}
