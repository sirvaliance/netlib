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
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.Date;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetSocket;

/**
 * NetSocket of transparent NetLayer that tracks the time stamp of the last activity.
 * 
 * @author hapke
 */
public class ControlNetSocket implements NetSocket {
    private static final Logger log = Logger.getLogger(ControlNetSocket.class.getName());

    private NetSocket lowerLayerSocket;
    
    private InputStream in;
    private OutputStream out;

    /** lastActivity - this field is currently not analyzed */
    private Date lastActivity;
    private Date startDate;
    private Date connectDate;
    private Date currentTimeframeStartDate;
    private long currentTimeframeStartInputOutputBytes;
    private long inputBytes;
    private long outputBytes;
    
    /** 
     * If the socket must be closed because of risen limit
     * then this field contains the exception that will be thrown be the streams
     */
    private InterruptedIOException interruptedIOException;

    public ControlNetSocket(NetSocket lowerLayerSocket, ControlParameters parameters) {
        this.startDate = new Date();
        this.currentTimeframeStartDate = startDate;
        this.currentTimeframeStartInputOutputBytes = 0L;
        this.lowerLayerSocket = lowerLayerSocket;
        setLastActivity();
        ControlNetSocketThread.startControlingControlNetSocket(this, parameters);
    }
    

    
    protected synchronized void addInputBytes(int bytes) {
        inputBytes+=bytes;
    }
    protected synchronized void addOutputBytes(int bytes) {
        outputBytes+=bytes;
    }
    
    protected void setLastActivity(Date lastActivity) {
        this.lastActivity = lastActivity;
    }
    protected void setLastActivity() {
        setLastActivity(new Date());
    }

    /**
     * @return    how many milliseconds of the current time frame are already gone
     */
    public long getCurrentTimeframeMillis() {
        Date now = new Date();
        return now.getTime()-currentTimeframeStartDate.getTime();
    }
    
    /**
     * @return    how many milliseconds are already gone
     */
    public long getOverallMillis() {
        Date now = new Date();
        return now.getTime()-startDate.getTime();
    }

    /**
     * Get data of the old time frame.
     * 
     * Start a new time frame (and reset all counters to start a fresh time frame).
     * 
     * @return    number of input+output byte transferred  during the old time frame
     */
    protected synchronized long getCurrentTimeframeStartInputOutputBytesAndStartNewTimeframe() {
        long result = getInputOutputBytes() - currentTimeframeStartInputOutputBytes;
        
        // "reset" the time frame
        currentTimeframeStartInputOutputBytes = getInputOutputBytes();
        Date now = new Date();
        currentTimeframeStartDate = now;
        return result;
    }

    
    public void close() throws IOException {
        lowerLayerSocket.close();
        ControlNetSocketThread.stopControlingControlNetSocket(this);
        setLastActivity();
    }

    public InputStream getInputStream() throws IOException {
        if (in==null) {
            in = new ControlInputStream(lowerLayerSocket.getInputStream(), this);
        }
        setLastActivity();
        return in;
    }

    public OutputStream getOutputStream() throws IOException {
        if (out==null) {
           out = new ControlOutputStream(lowerLayerSocket.getOutputStream(), this); 
        }
        setLastActivity();
        return out;
    }
    
    /**
     * Only same instance are equal.
     */
    @Override
    public int hashCode() {
        return super.hashCode();
    }
    
    /**
     * Only same instance are equal.
     */
    @Override
    public boolean equals(Object obj) {
        return super.equals(obj);
    }
    
    @Override
    public String toString() {
        return "ControlNetSocket("+lowerLayerSocket+")";
    }
    
    /** 
     * If the socket must be closed because of risen limit
     * then this field contains the exception that will be thrown be the streams
     * 
     * @param interruptedIOException
     */
    protected void setInterruptedIOException(InterruptedIOException interruptedIOException) {
        this.interruptedIOException = interruptedIOException;
    }
    /** 
     * If the socket must be closed because of risen limit
     * then this method throws the stored exception - intended to be forwarded to the streams.
     * 
     * @param interruptedIOException
     */
   protected void throwInterruptedIOExceptionIfNecessary() throws InterruptedIOException {
        if (interruptedIOException!=null) {
            throw interruptedIOException;
        }
    }
    
    ///////////////////////////////////////////////////////
    // various getters
    ///////////////////////////////////////////////////////

    public Date getStartDate() {
        return startDate;
    }
    public Date getConnectDate() {
        return connectDate;
    }
    public Date getCurrentTimeframeStartDate() {
        return currentTimeframeStartDate;
    }
    public long getCurrentTimeframeStartInputOutputBytes() {
        return currentTimeframeStartInputOutputBytes;
    }
    public long getInputBytes() {
        return inputBytes;
    }
    public long getOutputBytes() {
        return outputBytes;
    }
    public long getInputOutputBytes() {
        return inputBytes+outputBytes;
    }
    public Date getLastActivity() {
        return lastActivity;
    }
}
