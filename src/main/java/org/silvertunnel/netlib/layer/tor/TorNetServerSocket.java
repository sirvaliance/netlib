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

package org.silvertunnel.netlib.layer.tor;

import java.io.IOException;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetServerSocket;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.layer.tor.circuit.Circuit;
import org.silvertunnel.netlib.layer.tor.circuit.HiddenServiceInstance;
import org.silvertunnel.netlib.layer.tor.circuit.HiddenServicePortInstance;
import org.silvertunnel.netlib.layer.tor.stream.TCPStream;
import org.silvertunnel.netlib.layer.tor.util.TorException;

/**
 * NetServerSocket of Layer over Tor network to provide a hidden service.
 *  
 * @author hapke
 */
public class TorNetServerSocket implements NetServerSocket, HiddenServicePortInstance {
    private static final Logger log = Logger.getLogger(TorNetServerSocket.class.getName());

    private static final int SERVER_QUEUE_MAX_SIZE = 10;
    private BlockingQueue<TCPStream> streams = new ArrayBlockingQueue<TCPStream>(SERVER_QUEUE_MAX_SIZE, false);
    /** info used for toString() */
    private String info;
    private int port;
    private boolean closed = false;
    private HiddenServiceInstance hiddenServiceInstance;
    
    /**
     * Create a new TorNetServerSocket.
     * @param info    info used for toString()
     * @param port    listening port
     */
    public TorNetServerSocket(String info, int port) {
        this.info = info;
        this.port = port;
    }

    @Override
    public String toString() {
        return "TorNetServerSocket(info="+info+", port="+port+")";
    }
    
    ///////////////////////////////////////////////////////
    // methods to implement TorNetServerSocket
    ///////////////////////////////////////////////////////

    public NetSocket accept() throws IOException {
        log.info("accept() called");
        
        TCPStream nextStream = null;
        try {
            nextStream = streams.take();
        } catch (InterruptedException e) {
            log.log(Level.WARNING, "waiting interrupted", e);
        }
        log.info("accept() got stream from queue nextStream="+nextStream);
        
        return new TorNetSocket(nextStream, "TorNetLayer accepted server connection");
    }
 
    public void close() throws IOException {
        closed=true;
    }
 
    ///////////////////////////////////////////////////////
    // methods to implement HiddenServicePortInstance
    ///////////////////////////////////////////////////////
    
    public int getPort() {
        return port;
    }

    public boolean isOpen() {
        return !closed;
    }
    
    /**
     * Create a new (TCP)Stream and assign it to the circuit+streamId specified. 
     * @param circuit
     * @param streamId
     */
    public void createStream(Circuit circuit, int streamId) throws TorException, IOException {
        log.fine("addStream() called");
        TCPStream newStream = new TCPStream(circuit, streamId);
        try {
            streams.put(newStream);
        } catch (InterruptedException e) {
            log.log(Level.WARNING, "waiting interrupted", e);
        }
    }
 
    public HiddenServiceInstance getHiddenServiceInstance() {
        return hiddenServiceInstance;
    }

    public void setHiddenServiceInstance(HiddenServiceInstance hiddenServiceInstance) {
        this.hiddenServiceInstance = hiddenServiceInstance;
    }
}
