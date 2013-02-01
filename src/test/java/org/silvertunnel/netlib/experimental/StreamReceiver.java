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

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Experimental code.
 * 
 * OutputStream sender that
 * received bytes.
 *  
 * @author hapke
 */
public class StreamReceiver extends Thread {
    private static final Logger log = Logger.getLogger(StreamReceiver.class.getName());
    
    private volatile boolean stopped = false;

    private InputStream in;
    private String name;
    
    /**
     * Initialize.
     * 
     * @param name
     * @param out
     */
    public StreamReceiver(String name, InputStream in) {
        this.name = name;
        this.in = in;
    }

    @Override
    public void run() {
        try {
            while (!stopped) {
                // read and log one byte
                int oneByte = in.read();
                log.info(name+": received one byte="+oneByte);
                if (oneByte<0) {
                    log.info(name+": end of stream");
                    break;
                }
            }
            log.info(name+": loop stopped");
        } catch (Exception e) {
            log.log(Level.WARNING, name+": end because of exception", e);
        }
    }
    
    public void stopNow() {
        log.info(name+": stopNow");
        this.stopped = true;
        try {
            in.close();
        } catch (IOException e) {
            log.log(Level.WARNING, name, e);
        }
    }

    ///////////////////////////////////////////////////////
    // getters and setters
    ///////////////////////////////////////////////////////
    public boolean isStopped() {
        return stopped;
    }
}
