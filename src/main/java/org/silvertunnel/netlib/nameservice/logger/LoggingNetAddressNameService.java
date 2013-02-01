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

package org.silvertunnel.netlib.nameservice.logger;

import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetAddressNameService;

/**
 * Log name service requests
 * and forward the requests to the lower name service.
 * 
 * @author hapke
 */
public class LoggingNetAddressNameService implements NetAddressNameService {
    private static Logger defaultLog = Logger.getLogger(LoggingNetAddressNameService.class.getName());

    private NetAddressNameService lowerNetAddressNameService;
    private Logger log;
    private Level logLevel;
    private String loggingPrefix;
    
    /**
     * Initialize this name service. Log to default logger.
     * 
     * @param lowerNetAddressNameService    service that has to answer the name service requests 
     * @param logLevel
     */
    public LoggingNetAddressNameService(NetAddressNameService lowerNetAddressNameService, Level logLevel) {
        this(lowerNetAddressNameService, logLevel, null);
    }

    /**
     * Initialize this name service. Log to default logger.
     * 
     * @param lowerNetAddressNameService    service that has to answer the name service requests 
     * @param logLevel
     * @param loggingPrefix                 can be null
     */
    public LoggingNetAddressNameService(NetAddressNameService lowerNetAddressNameService, Level logLevel, String loggingPrefix) {
        this(lowerNetAddressNameService, defaultLog, logLevel, loggingPrefix);
    }

    /**
     * Initialize this name service.
     * 
     * @param lowerNetAddressNameService    service that has to answer the name service requests 
     * @param log
     * @param logLevel
     * @param loggingPrefix                 can be null
     */
    public LoggingNetAddressNameService(NetAddressNameService lowerNetAddressNameService, Logger log, Level logLevel, String loggingPrefix) {
        this.lowerNetAddressNameService = lowerNetAddressNameService;
        this.log = log;
        this.logLevel = logLevel;
        this.loggingPrefix = (loggingPrefix!=null)  ?  (loggingPrefix+": ")  :  ("");
    }

    
    
    /** @see NetAddressNameService#getAddresses */
    public NetAddress[] getAddressesByName(String name) throws UnknownHostException {
        boolean normalEnd = false;
        boolean unknownHostExceptionEnd = false;
        
        try {
            log.log(logLevel, loggingPrefix+"getAddresses(name=\""+name+"\") called");
            
            // action
            NetAddress[] result = lowerNetAddressNameService.getAddressesByName(name);
            
            String resultStr = (result==null) ? null : Arrays.toString(result);
            log.log(logLevel, loggingPrefix+"  getAddresses(name=\""+name+"\") result="+resultStr);
            normalEnd = true;
            
            return result;
            
        } catch (UnknownHostException e) {
            log.log(logLevel, loggingPrefix+"  getAddresses(name=\""+name+"\") throws "+e.toString());
            unknownHostExceptionEnd = true;
            throw e;
            
        } finally {
            if ((!normalEnd) && (!unknownHostExceptionEnd)) {
                log.log(logLevel, loggingPrefix+"  getAddresses(name=\""+name+"\") throws UNCATHCHED EXCEPTION");
            }
        }
    }

    /** @see NetAddressNameService#getNames */
    public String[] getNamesByAddress(NetAddress address) throws UnknownHostException {
        boolean normalEnd = false;
        boolean unknownHostExceptionEnd = false;
        
        try {
            log.log(logLevel, loggingPrefix+"getNames(address=\""+address+"\") called");
            
            // action
            String[] result = lowerNetAddressNameService.getNamesByAddress(address);
            
            String resultStr = (result==null) ? null : Arrays.toString(result);
            log.log(logLevel, loggingPrefix+"  getNames(address=\""+address+"\") result="+resultStr);
            normalEnd = true;
            
            return result;
            
        } catch (UnknownHostException e) {
            log.log(logLevel, loggingPrefix+"  getNames(address=\""+address+"\") throws "+e.toString());
            unknownHostExceptionEnd = true;
            throw e;
            
        } finally {
            if ((!normalEnd) && (!unknownHostExceptionEnd)) {
                log.log(logLevel, loggingPrefix+"  getNames(address=\""+address+"\") throws UNCATHCHED EXCEPTION");
            }
        }
    }
}
