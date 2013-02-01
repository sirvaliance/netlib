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
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetSocket;

/**
 * NetSocket of transparent NetLayer that logs input and output streams.
 * 
 * @author hapke
 */
public class LoggingNetSocket implements NetSocket {
    private NetSocket lowerLayerSocket;
    private Logger summaryLog;
    private Level  summaryLogLevel;
    private Logger detailLog;
    private Level  detailLogLevel;
    private boolean logContent;
    private String topDownLoggingPrefix;
    private String bottomUpLoggingPrefix;
    
    private InputStream in;
    private OutputStream out;

    
    public LoggingNetSocket(NetSocket lowerLayerSocket, Logger summaryLog, Level summaryLogLevel, Logger detailLog, Level  detailLogLevel, 
            boolean logContent, String topDownLoggingPrefix, String bottomUpLoggingPrefix) {
        this.lowerLayerSocket = lowerLayerSocket;
        this.summaryLog = summaryLog;
        this.summaryLogLevel = summaryLogLevel;
        this.detailLog = detailLog;
        this.detailLogLevel = detailLogLevel;
        this.logContent = logContent;
        this.topDownLoggingPrefix = topDownLoggingPrefix;
        this.bottomUpLoggingPrefix = bottomUpLoggingPrefix;
    }
    
    public void close() throws IOException {
        lowerLayerSocket.close();
    }

    public InputStream getInputStream() throws IOException {
        if (in==null) {
            BufferedLogger bufferedLogger = new BufferedLogger(summaryLog, summaryLogLevel, detailLog, detailLogLevel, logContent, bottomUpLoggingPrefix);
            in = new LoggingInputStream(lowerLayerSocket.getInputStream(), bufferedLogger);
        }
        return in;
    }

    public OutputStream getOutputStream() throws IOException {
        if (out==null) {
            BufferedLogger bufferedLogger = new BufferedLogger(summaryLog, summaryLogLevel, detailLog, detailLogLevel, logContent, topDownLoggingPrefix);
            out = new LoggingOutputStream(lowerLayerSocket.getOutputStream(), bufferedLogger); 
        }
        return out;
    }
    
    @Override
    public String toString() {
        return "LoggingNetSocket("+lowerLayerSocket+")";
    }
}
