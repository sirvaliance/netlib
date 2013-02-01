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

package org.silvertunnel.netlib.layer.logger;

import java.io.IOException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetAddressNameService;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerStatus;
import org.silvertunnel.netlib.api.NetServerSocket;
import org.silvertunnel.netlib.api.NetSocket;

/**
 * Transparent NetLayer that logs input and output streams.
 * 
 * @author hapke
 */
public class LoggingNetLayer implements NetLayer {
    private static Logger defaultLog = Logger.getLogger(LoggingNetLayer.class.getName());

    private NetLayer lowerNetLayer;
    private Logger summaryLog;
    private Level  summaryLogLevel;
    private Logger detailLog;
    private Level  detailLogLevel;
    private boolean logContent;
    private String topDownLoggingPrefix;
    private String bottomUpLoggingPrefix;
    
    /** counter of connection attempts of all LoggingNetLayer instances */
    private static long connectionAttemptsGlobalCounter = 0;

    /** counter of connection attempts of this LoggingNetLayer instance */
    private long connectionAttemptsCounter = 0;

    /** counter of successfully established connections of this LoggingNetLayer instance */
    private long connectionEstablisedCounter = 0;
    
    /**
     * Initialize a new layer with default parameters.
     * 
     * summaryLogLevel=Level.FINE
     *  detailLogLevel=Level.FINER
     * 
     * @param lowerNetLayer
     * @param logLevel
     * @param logContent       true=log detailed content of all traffic; false=log summary information only
     * @param loggingPrefix    String that is always logged
     */
    public LoggingNetLayer(NetLayer lowerNetLayer, String loggingPrefix) {
        this(lowerNetLayer,
                Logger.getLogger(lowerNetLayer.getClass().getName()), Level.FINE,
                Logger.getLogger(lowerNetLayer.getClass().getName()), Level.FINER,
                true, 
                "v [down] "+loggingPrefix+": ",
                "^ [up]   "+loggingPrefix+": ");
    }
    
    /**
     * Initialize a new layer.
     * 
     * @param lowerNetLayer
     * @param summaryLog
     * @param summaryLogLevel
     * @param logContent       true=log detailed content of all traffic; false=log summary information only
     * @param topDownLoggingPrefix
     * @param bottomUpLoggingPrefix
     */
    public LoggingNetLayer(NetLayer lowerNetLayer, Logger summaryLog, Level summaryLogLevel, Logger detailLog, Level detailLogLevel,
            boolean logContent, String topDownLoggingPrefix, String bottomUpLoggingPrefix) {
        this.lowerNetLayer = lowerNetLayer;
        this.summaryLog = summaryLog;
        this.summaryLogLevel = summaryLogLevel;
        this.detailLog = detailLog;
        this.detailLogLevel = detailLogLevel;
        this.logContent = logContent;
        this.topDownLoggingPrefix = topDownLoggingPrefix;
        this.bottomUpLoggingPrefix = bottomUpLoggingPrefix;
    }
    
    /** @see NetLayer#createNetSocket */
    public NetSocket createNetSocket(Map<String,Object> localProperties, NetAddress localAddress, NetAddress remoteAddress) throws IOException {
        // log this method call
        String connectionIdStr = "<conn="+getNextConnectionAttemptGlobalCounter()+"> ";
        synchronized (this) {
            connectionAttemptsCounter++;
        }
        BufferedLogger tmpLog = new BufferedLogger(summaryLog, summaryLogLevel, detailLog, detailLogLevel, logContent, connectionIdStr+topDownLoggingPrefix);
        tmpLog.logSummaryLine("createNetSocket with localProperties="+localProperties+", localAddress="+localAddress+", remoteAddress="+remoteAddress);
        
        // action
        NetSocket lowerLayerSocket = lowerNetLayer.createNetSocket(localProperties, localAddress, remoteAddress);
        NetSocket result = new LoggingNetSocket(lowerLayerSocket, summaryLog, summaryLogLevel, detailLog, detailLogLevel, logContent,
                connectionIdStr+topDownLoggingPrefix,
                connectionIdStr+bottomUpLoggingPrefix);
        tmpLog.logSummaryLine("createNetSocket was successful for lowerLayerSocket="+lowerLayerSocket);
        
        // update 2nd counter
        synchronized (this) {
            connectionEstablisedCounter++;
        }
        
        return result;
    }

    /** @see NetLayer#createNetServerSocket */
    public NetServerSocket createNetServerSocket(Map<String,Object> properties, NetAddress localListenAddress) throws IOException {
        // TODO: include better logging
        String connectionIdStr = "<server-conn="+getNextConnectionAttemptGlobalCounter()+"> ";
        BufferedLogger tmpLog = new BufferedLogger(summaryLog, summaryLogLevel, detailLog, detailLogLevel, logContent, connectionIdStr+topDownLoggingPrefix);
        tmpLog.logSummaryLine("createNetSocket with properties="+properties+", localListenAddress="+localListenAddress);
        
        return lowerNetLayer.createNetServerSocket(properties, localListenAddress);
    }
    
    /**
     * Get an (almost unique) ID of a connection - for better logging results.
     * @return the ID
     */
    protected static synchronized long getNextConnectionAttemptGlobalCounter() {
        connectionAttemptsGlobalCounter++;
        if (connectionAttemptsGlobalCounter<0) {
            connectionAttemptsGlobalCounter=1;
        }
        return connectionAttemptsGlobalCounter;
    }
    

    
    /** @see NetLayer#getStatus() */
    public NetLayerStatus getStatus() {
        return lowerNetLayer.getStatus();
    }
    
    /** @see NetLayer#waitUntilReady() */
    public void waitUntilReady() {
        lowerNetLayer.waitUntilReady();
    }

    /** @see NetLayer#clear() */
    public void clear() throws IOException {
        lowerNetLayer.clear();
    }
    
    /** @see NetLayer#getNetAddressNameService() */
    public NetAddressNameService getNetAddressNameService() {
        return lowerNetLayer.getNetAddressNameService();
    }
   
    ///////////////////////////////////////////////////////
    // methods to provide statistical information, e.g. used by JUnit test cases
    ///////////////////////////////////////////////////////

    /**
     * @return counter of connection attempts of all LoggingNetLayer instances
     */
    public static synchronized long getConnectionAttemptsGlobalCounter() {
        return connectionAttemptsGlobalCounter;
    }
    /**
     * @return counter of connection attempts of this LoggingNetLayer instance
     */
    public synchronized long getConnectionAttemptsCounter() {
        return connectionAttemptsCounter;
    }

    /**
     * @return counter of successfully established connection of this LoggingNetLayer instance
     */
    public synchronized long getConnectionEstablisedCounter() {
        return connectionEstablisedCounter;
    }
}
