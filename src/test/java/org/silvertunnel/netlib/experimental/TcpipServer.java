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

package org.silvertunnel.netlib.experimental;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Experimental code.
 * 
 * TCP/IP server that can handle one connection request.
 *  
 * @author hapke
 */
public class TcpipServer extends Thread {
    private static final Logger log = Logger.getLogger(TcpipServer.class.getName());
    
    public static int SERVER_PORT = 11223;
    public static final String name = "                                                                  TcpipServer";
    
    private StreamSender streamSender;
    private StreamReceiver streamReceiver;
    private Socket socket; 
    
    /**
     * Start a TCP server (socket) that can handle one connection request.
     */
    public void run() {
        try {
            ServerSocket ss = new ServerSocket(SERVER_PORT);
            log.info(name+": server socket started");
            
            socket = ss.accept();
            log.info(name+": connection accepted");
            
            // start handling threads
            streamReceiver = new StreamReceiver(name+"-receiv", socket.getInputStream());
            streamReceiver.start();
            streamSender = new StreamSender(    name+"-sender", socket.getOutputStream(), (byte)100);
            streamSender.start();

            log.info(name+": receiver and sender threads started");

        } catch (Exception e) {
            log.log(Level.WARNING, name+": end because of exception", e);
        }
    }


    ///////////////////////////////////////////////////////
    // getters and setters
    ///////////////////////////////////////////////////////
    public StreamSender getStreamSender() {
        return streamSender;
    }

    public StreamReceiver getStreamReceiver() {
        return streamReceiver;
    }

    public Socket getSocket() {
        return socket;
    }
}
