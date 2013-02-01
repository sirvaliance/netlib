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

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.api.NetServerSocket;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;

/**
 * Command line tool that starts a proxy that connects to a NetLayer.
 * 
 * The connection client-proxy is uses TCP/IP,
 * the connection proxy-restOfTheWorld uses the specified NetLayer.
 * 
 * Command line arguments:
 *     [optional_listen_address:listen_port] [net_layer_id] [prop1=value1] [prop2=value2] ...
 * 
 * Examples:
 *     java -cp ... org.silvertunnel.netlib.tool.NetlibProxy 1080 socks_over_tcpip
 *     java -cp ... org.silvertunnel.netlib.tool.NetlibProxy 127.0.0.1:1080 socks_over_tcpip
 *     java -cp ... org.silvertunnel.netlib.tool.NetlibProxy [::1/128]:1080 socks_over_tcpip       (IPv6 - not yet implemented)
 *     java -cp ... org.silvertunnel.netlib.tool.NetlibProxy 127.0.0.1:1080 socks_over_tor_over_tls_over_tcpip
 *     java -cp ... -DNetLayerBootstrap.skipTor=true org.silvertunnel.netlib.tool.NetlibProxy 1080 socks_over_tcpip TcpipNetLayer.backlog=10
 *
 * @author hapke
 */
public class NetlibProxy {
    private static final Logger log = Logger.getLogger(NetlibProxy.class.getName());

    private static boolean startedFromCommandLine = true;
    private static volatile boolean started = false;
    private static volatile boolean stopped = false;
    private static NetServerSocket netServerSocket;
    
    /**
     * Start the program, but not from command line.
     * 
     * @param argv
     */
    public static void start(String[] argv) {
        startedFromCommandLine = false;
        main(argv);
    }
    
    /**
     * Start the program from command line.
     * 
     * @param argv
     */
    public static void main(String[] argv) {
        stopped = false;
        started = false;
        if (argv.length<1) {
            log.severe("NetProxy: insufficient number of command line arguments: you must specify [listen_port] and [net_layer_id] at least");
            System.exit(1);
            return;
        }

        // open server port
        try {
            // parse listen address and port
            String listenAddressPortArg = argv[0];
            TcpipNetAddress localListenAddress = new TcpipNetAddress(listenAddressPortArg);
            
            // open server port
            netServerSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP).createNetServerSocket(null, localListenAddress);

        } catch (Exception e) {
            log.log(Level.SEVERE, "NetlibProxy: could not open server port", e);
            if (startedFromCommandLine) {
                log.severe("System.exit(2)");
                System.exit(2);
            }
            return;
        }
        started = true;
        
        // parse the netLayerId
        String lowerLayerNetLayerId = argv[1];

        // handle incoming connections (listen endless)
        try {
            while(!stopped) {
                NetSocket upperLayerNetSocket = netServerSocket.accept();
                new NetProxySingleConnectionThread(upperLayerNetSocket, lowerLayerNetLayerId).start();
            }
        } catch (Exception e) {
            started = false;
            String msg = "NetlibProxy: server-wide problem while running"; 
            if (stopped) {
                log.info(msg);
            } else {
                log.log(Level.SEVERE, msg, e);
            }
            if (startedFromCommandLine) {
                log.severe("System.exit(3)");
                System.exit(3);
            }
            return;
        }
    }

    /**
     * (Try to) close/exit the program.
     */
    public static void stop() {
        log.info("NetlibProxy: will be stopped now");
        stopped = true;
        started = false;
        
        // close server socket
        try {
            netServerSocket.close();
        } catch (IOException e) {
            log.log(Level.WARNING, "Exception while closing the server socket", e);
        }
    }
    
    /**
     * Retrieve the current state.
     * 
     * @return true=proxy server port is open
     */
    public static boolean isStarted() {
        return started;
    }
    
    ///////////////////////////////////////////////////////
    // test code
    ///////////////////////////////////////////////////////
    
    public static void testConnection() throws Exception {
        log.info("(client) connect client to server");
        TcpipNetAddress remoteAddress = new TcpipNetAddress("www.google.de", 80);
        NetSocket client = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP).createNetSocket(null, null, remoteAddress);
        
        log.info("(client) send data client->server");
        client.getOutputStream().write("GET /\n\n".getBytes());
        client.getOutputStream().flush();
        
        log.info("(client) read data from server");
        byte[] dataReceivedByClient  = readDataFromInputStream(100, client.getInputStream());
        
        log.info("(client) finish connection");
        client.close();
    }
    public static byte[] readDataFromInputStream(int maxResultSize, InputStream is) throws IOException {
        byte[] tempResultBuffer = new byte[maxResultSize];
        
        int len = 0;
        do {
            if (len>=tempResultBuffer.length) {
                //log.info("result buffer is full");
                break;
            }
            int lastLen=is.read(tempResultBuffer, len, tempResultBuffer.length-len);
            if (lastLen<0) {
                //log.info("end of result stream");
                break;
            }
            len+=lastLen;
        } while (true);
    
        // copy to result buffer
        byte[] result = new byte[len];
        System.arraycopy(tempResultBuffer, 0, result, 0, len);
        
        return result;
    }
}
