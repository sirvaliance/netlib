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

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Log bytes - but delay the logging until the next flush.
 * 
 * @author hapke
 */
public class BufferedLogger {
    public static final Level LOG_LEVEL_NULL = Level.OFF;
    public static final Level LOG_LEVEL_DEBUG = Level.FINE;
    public static final Level LOG_LEVEL_INFO = Level.INFO;
    private static final char SPECIAL_CHAR = '?';
    
    private Logger summaryLog;
    private Level  summaryLogLevel;
    private Logger detailLog;
    private Level  detailLogLevel;
    private boolean logSingleBytes;
    private String logMessagePrefix;
    
    private StringBuffer buffer = new StringBuffer();
    int byteCount = 0;

    /**
     * Initialize a new BufferedLogger.
     * 
     * @param summaryLog
     * @param summaryLogLevel
     * @param logSingleBytes
     * @param logMessagePrefix
     */
    public BufferedLogger(Logger summaryLog, Level summaryLogLevel, Logger detailLog, Level  detailLogLevel, boolean logSingleBytes, String logMessagePrefix) {
        this.summaryLog = summaryLog;
        this.summaryLogLevel = summaryLogLevel;
        this.detailLog = detailLog;
        this.detailLogLevel = detailLogLevel;
        this.logSingleBytes = logSingleBytes;
        this.logMessagePrefix = logMessagePrefix;
    }
    
    /**
     * log b - but delay the logging until the next flush.
     * 
     * @param b
     */
    public void log(byte b) {
        if (logSingleBytes && detailLog.isLoggable(detailLogLevel)) {
            char c = (char)b;
            if (c>=' ' && c<=0x7f) {
                logAndCount(c);
            } else {
                logAndCount(SPECIAL_CHAR);
                // add hex value (always two digits)
                int i = b<0 ? 256+b : b;
                String hex = Integer.toHexString(i);
                if (hex.length()<2) {
                    logAndDoNotCount("0");
                }
                logAndDoNotCount(hex);
            }
        } else {
            byteCount++;
        }
    }
    
    /**
     * log bytes - but delay the logging until the next flush.
     * 
     * @param bytes
     * @param offset        start at this array index in bytes
     * @param numOfBytes    log this number of bytes
     */
    public void log(byte[] bytes, int offset, int numOfBytes) {
        if (logSingleBytes && detailLog.isLoggable(detailLogLevel)) {
            int len = bytes.length;
            for (int i=0; i<numOfBytes; i++) {
                int idx = offset+i;
                if (idx<len) {
                    log((byte)bytes[idx]);
                }
            }
        } else {
            byteCount += numOfBytes;
        }
    }

    private void logAndCount(char c) {
        buffer.append(c);
        byteCount++;
    }
    private void logAndDoNotCount(String s) {
        buffer.append(s);
    }
    
    /**
     * Log out the current buffer.
     */
    public void flush() {
        if (buffer.length()>0) {
            if (detailLog.isLoggable(detailLogLevel)) {
                String msg = byteCount+" bytes \""+buffer.toString()+"\"";
                logDetailLine(msg);
            }
            byteCount = 0;
            buffer = new StringBuffer();
        }
        if (byteCount>0) {
            if (detailLog.isLoggable(detailLogLevel)) {
                logDetailLine(byteCount+" bytes");
            }
            byteCount = 0;
            buffer = new StringBuffer();
        }
    }

    /**
     * Directly log msg, without current stack trace.
     * 
     * @param msg
     */
    public void logSummaryLine(String msg) {
        logLine(summaryLog, summaryLogLevel, msg, false);
    }

    /**
     * Directly log msg, without current stack trace.
     * 
     * @param msg
     */
    public void logDetailLine(String msg) {
        logLine(detailLog, detailLogLevel, msg, false);
    }

    /**
     * Directly log msg.
     * 
     * @param logger
     * @param level
     * @param msg
     * @param withStackTrace    true=log inclused current stack trace
     */
    public void logLine(Logger logger, Level level, String msg, boolean withStackTrace) {
        String finalMsg = logMessagePrefix+msg;
        if (withStackTrace) {
            logger.log(level, finalMsg, new Throwable());
        } else {
            logger.log(level, finalMsg);
        }
    }
    
    public boolean isLogSingleBytesEnabled() {
        return logSingleBytes;
    }
}
