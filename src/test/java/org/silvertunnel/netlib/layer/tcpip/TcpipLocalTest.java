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

import java.io.IOException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Before;
import org.junit.Test;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.api.NetServerSocket;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.layer.logger.LoggingNetLayer;
import org.silvertunnel.netlib.util.ByteArrayUtil;

/**
 * Test of TcpipNetLayer.
 */
public class TcpipLocalTest {
    static Logger log = Logger.getLogger(TcpipLocalTest.class.getName());

    static final int TEST_SERVER_PORT = 9999;

    static final byte[] DATA_CLIENT_TO_SERVER = ByteArrayUtil.getByteArray("Send me to the server...", 2000, "...!!!");
    static final byte[] DATA_SERVER_TO_CLIENT = ByteArrayUtil.getByteArray("The server speaks...", 3000, "...OK");
    
    volatile static byte[] dataReceivedByServer;
    volatile static byte[] dataReceivedByClient;
    
    @Before
    public void setUp() throws Exception {
        // create layer for modify_over_tcpip
        NetLayer tcpipNetLayer = new TcpipNetLayer();
        NetLayer loggedTcpiNetLayer = new LoggingNetLayer(tcpipNetLayer, "upper tcp");
        NetFactory.getInstance().registerNetLayer(NetLayerIDs.TCPIP, loggedTcpiNetLayer);
    }
    
    @Test(timeout=3000)
    public void testServerClientConnection() throws Exception {
        // start server
        new TcpipLocalTestServerThread().start();
        
        log.info("(client) connect client to server");
        TcpipNetAddress remoteAddress = new TcpipNetAddress("localhost", TEST_SERVER_PORT);
        NetSocket client = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP).
        		createNetSocket(null, null, remoteAddress);
        
        log.info("(client) send data client->server");
        client.getOutputStream().write(DATA_CLIENT_TO_SERVER);
        client.getOutputStream().flush();
        
        log.info("(client) read data from server");
        dataReceivedByClient  = ByteArrayUtil.readDataFromInputStream(DATA_SERVER_TO_CLIENT.length, client.getInputStream());
        
        log.info("(client) finish connection");
        client.close();
        
        log.info("(client) wait for end");
        while (dataReceivedByServer==null) {
            Thread.sleep(100);
        }
        
        // check result
        assertEquals("wrong dataReceivedByServer", Arrays.toString(DATA_CLIENT_TO_SERVER), Arrays.toString(dataReceivedByServer));
        assertEquals("wrong dataReceivedByClient", Arrays.toString(DATA_SERVER_TO_CLIENT), Arrays.toString(dataReceivedByClient));
    }
}

class TcpipLocalTestServerThread extends Thread {
    private NetServerSocket server;
    
    public TcpipLocalTestServerThread() {
        try {
            //setDaemon(true);
            TcpipLocalTest.log.info("(server) create server socket");
            TcpipNetAddress localListenAddress = new TcpipNetAddress("0.0.0.0", TcpipLocalTest.TEST_SERVER_PORT);
            server = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP).
            		createNetServerSocket(null, localListenAddress);

        } catch (IOException e) {
            TcpipLocalTest.log.log(Level.WARNING, "exception", e);
        }
    }
    
    public void run() {
        try {
            TcpipLocalTest.log.info("(server) wait for one connection");
            NetSocket s = server.accept();
            server.close();
            
            TcpipLocalTest.log.info("(server) send data from server->client");
            s.getOutputStream().write(TcpipLocalTest.DATA_SERVER_TO_CLIENT);
            s.getOutputStream().flush();

            TcpipLocalTest.log.info("(server) read data from client");
            TcpipLocalTest.dataReceivedByServer  = ByteArrayUtil.readDataFromInputStream(TcpipLocalTest.DATA_CLIENT_TO_SERVER.length, s.getInputStream());
            TcpipLocalTest.log.info("(server) reading finished");
            
        } catch (IOException e) {
            TcpipLocalTest.log.log(Level.WARNING, "exception", e);
        }
    }
}
