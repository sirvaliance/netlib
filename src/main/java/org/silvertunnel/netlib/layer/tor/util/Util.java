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

package org.silvertunnel.netlib.layer.tor.util;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.logging.Logger;


/**
 * Helper method for Tor.
 * 
 * @author hapke
 */
public class Util {
    private static final Logger log = Logger.getLogger(Util.class.getName());

    public static final String MYNAME = "silvertunnel-org-Netlib";

    public static final String UTF8 = "UTF-8";
    
    private static final String UTC_TIMESTAMP_FORMAT = "yyyy-MM-dd HH:mm:ss";
    private static DateFormat utcTimestampDateFormat;
    
    
    /**
     * no synchronization inside this method!
     * 
     * After executing utcTimestampDateFormat is initialized.
     */
    private static void initUtcTimestampIfNeeded() {
        if (utcTimestampDateFormat==null) {
            // initialize date format
            utcTimestampDateFormat = new SimpleDateFormat(UTC_TIMESTAMP_FORMAT);
            utcTimestampDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        }
    }
    
    /**
     * Parse with format "yyyy-MM-dd HH:mm:ss".
     * 
     * @param timestampStr    interpret the time as UTC
     * @return the time stamp; null in the case of an error
     */
    public static Date parseUtcTimestamp(String timestampStr) {
        try {
            // synchronized because SimpleDateFormat is not thread safe
            synchronized(Util.class) {
                initUtcTimestampIfNeeded();

                // parse
                return utcTimestampDateFormat.parse(timestampStr);
            }

        } catch (Exception e) {
            log.fine(e.toString()+" while parsing timestampStr="+timestampStr);
            return null;
        }
    }
    
    /**
     * Format with format "yyyy-MM-dd HH:mm:ss".
     * 
     * @param timestamp
     * @return the timestamp as UTC; null in the case of an error
     */
    public static String formatUtcTimestamp(Date timestamp) {
        try {
            // synchronized because SimpleDateFormat is not thread safe
            synchronized(Util.class) {
                initUtcTimestampIfNeeded();

                // parse
                return utcTimestampDateFormat.format(timestamp);
            }
        } catch (Exception e) {
            log.fine(e.toString()+" while formatting timestamp="+timestamp);
            return null;
        }
    }
}
