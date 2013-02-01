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

package org.silvertunnel.netlib.layer.control;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * NetSocket of transparent NetLayer that tracks the time stamp of the last activity.
 * 
 * @author hapke
 */
public class ControlNetSocketThread extends Thread {
    private static final Logger log = Logger.getLogger(ControlNetSocketThread.class.getName());
    
    private static ControlNetSocketThread instance;
    
    /** all ControlNetSockets to control */
    private Map<ControlNetSocket,ControlParameters> sockets =
        Collections.synchronizedMap(new WeakHashMap<ControlNetSocket,ControlParameters>());
    
    static {
        try {
            // first class access: start a single instance of this thread now
            instance = new ControlNetSocketThread();
            instance.setName("ControlNetSocketThread");
            instance.setDaemon(true);
            instance.start();
            log.info("ControlNetSocketThread instance started");
            
        } catch (Throwable t) {
            log.log(Level.SEVERE, "could not construct class ControlNetSocketThread", t);
        }
    }

    /**
     * Start checking on ControlNetSocket with the provided ControlParameters.
     * 
     * @param socket
     * @param parameters
     */
    public static void startControlingControlNetSocket(ControlNetSocket socket, ControlParameters parameters) {
        synchronized(instance.sockets) {
            instance.sockets.put(socket, parameters);
        }
    }
    /**
     * Stop checking on ControlNetSocket.
     * 
     * @param socket
     */
    public static void stopControlingControlNetSocket(ControlNetSocket socket) {
        synchronized(instance.sockets) {
            instance.sockets.remove(socket);
        }
    }

    
    @Override
    public void run() {
        while (true) {
            // check all sockets
            Map<ControlNetSocket,String> socketsToRemoveFromChecklist = new HashMap<ControlNetSocket,String>(); // value=timeout text
            synchronized(sockets) {
                Date now = new Date();
                for (Entry<ControlNetSocket,ControlParameters> e : sockets.entrySet()) {
                    // check one socket
                    String timeoutText = checkSingleSocketOnce(e.getKey(), e.getValue(), now);
                    if (timeoutText!=null) {
                        socketsToRemoveFromChecklist.put(e.getKey(), timeoutText);
                    }
                }
            
                // cleanup sockets
                for (Entry<ControlNetSocket,String> e : socketsToRemoveFromChecklist.entrySet()) {
                    sockets.remove(e.getKey());
                }
            }
            
            // close sockets that timed out
            for (Entry<ControlNetSocket,String> e : socketsToRemoveFromChecklist.entrySet()) {
                sendTimeoutToSingleSocket(e.getKey(), e.getValue());
            }
            
            // wait a bit
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) { /* ignore it */ }
        }
    }
    
    /**
     * Check whether socket should be closed.
     * 
     * @param socket
     * @param parameters
     * @param now
     * @return error message:
     *         null=no timeout
     *         text=timeout with this text
     */
    private String checkSingleSocketOnce(ControlNetSocket socket, ControlParameters parameters, Date now) {
        // check overall timeout
        if (parameters.getOverallTimeoutMillis() > 0 &&
            socket.getOverallMillis() > parameters.getOverallTimeoutMillis()) {
            // timeout!!!
            return "overall timeout reached";
        }
        if (parameters.getThroughputTimeframeMillis()>0 &&
            socket.getCurrentTimeframeMillis() >= parameters.getThroughputTimeframeMillis()) {
            // current time frame is over
            long bytes = socket.getCurrentTimeframeStartInputOutputBytesAndStartNewTimeframe();
            if (parameters.getThroughputTimeframeMinBytes()>0 &&
                bytes < parameters.getThroughputTimeframeMinBytes()) {
                // timeout!!!
                return "throughput is too low";
            }
        }
        
        // no timeout
        return null;
    }
        
    private void sendTimeoutToSingleSocket(ControlNetSocket socket, String msg) {
        log.info("send timeout to "+socket+": "+msg);
        try {
            InterruptedIOException exceptionToBeThrownBySockets = new InterruptedIOException("Stream of ControlNetLayer closed because of: "+msg);
            socket.setInterruptedIOException(exceptionToBeThrownBySockets);
            socket.close();
        } catch (IOException e) {
            log.log(Level.FINE, "IOException while calling close() (want to close because of: "+msg+")", e);
        } catch (Exception e) {
            log.log(Level.INFO, "Exception while calling close() (want to close because of: "+msg+")", e);
        }
    }
}
