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
package org.silvertunnel.netlib.layer.tor.stream;

import java.util.logging.Logger;

import org.silvertunnel.netlib.layer.tor.circuit.Circuit;
import org.silvertunnel.netlib.layer.tor.common.TCPStreamProperties;

/**
 * this class is used to build a TCPStream in the background
 * 
 * @author Lexi
 * @author hapke
 */
public class StreamThread extends Thread {
    private static final Logger log = Logger.getLogger(StreamThread.class.getName());

    private TCPStream stream;
    private Circuit cs;
    private TCPStreamProperties sp;
    //private boolean finished = false;

    /** copy data to local variables and start background thread */
    public StreamThread(Circuit cs, TCPStreamProperties sp) {
        this.cs = cs;
        this.sp = sp;
        this.start();
    }

    /**
     * build stream in background and return. possibly the stream is closed
     * prematurely by another thread by having its queue closed
     */
    public void run() {
        try {
            stream = new TCPStream(cs, sp);

        } catch (Exception e) {
            if ((stream != null) && (stream.getQueue() != null) && (!stream.getQueue().isClosed())) {
                log.warning("Tor.StreamThread.run(): " + e.getMessage());
            }
            stream = null;
        }
        //finished = true;
    }
    
    public TCPStream getStream() {
        return stream;
    }
}
