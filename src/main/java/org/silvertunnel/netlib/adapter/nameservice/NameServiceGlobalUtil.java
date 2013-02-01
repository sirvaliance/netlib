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

package org.silvertunnel.netlib.adapter.nameservice;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetAddressNameService;
import org.silvertunnel.netlib.nameservice.mock.NopNetAddressNameService;

/**
 * This class allows modification of the JVM global socket handling.
 * 
 * This class contains Java version specific code and does maybe not always work!
 * Detailed description: http://sourceforge.net/apps/trac/silvertunnel/wiki/Netlib+Name+Service+Adapter
 * 
 * @author hapke
 */
public class NameServiceGlobalUtil {
    private static final Logger log = Logger.getLogger(NameServiceGlobalUtil.class.getName());

    private static boolean initialized = false;
    private static boolean initializedWithSuccess = false;

    /**
     * time to circumvent caching (maximum of networkaddress.cache.ttl and networkaddress.cache.negative.ttl) in milliseconds
     * 
     * 10 seconds + a bit because Windwos JVMs need a bit more.
     */
    private static final long CACHE_TIMEOUT_MILLIS = 11000;
    
    /**
     * Initialize the NameService of class java.net.InetAddress.
     * 
     * This method call influences the complete Java JVM.
     * 
     * This method can be called multiple times without any problems,
     * but it must be called before the first usage/before the class initialization
     * of class java.net.InetAddress.
     * 
     * If this method cannot be called before initialization of class java.net.InetAddress
     * we have a (first quality) way:
     * try to call this method in the static initializer of your calling class.
     * 
     * If this method cannot be called before initialization of class java.net.InetAddress
     * we have a (second quality) alternative:
     * set the following system properties when starting the JVM
     * (e.g. with use of "-Dkey=value" command line arguments):
     *     sun.net.spi.nameservice.provider.1=dns,NetlibNameService
     *     (properties to disable name service caching,set TTL to 0)
     * Disabling the name service caching is needed to be able to change the lower NetAddressNameService.
     *     
     * The first lower NetAddressNameService is NopNetAddressNameService
     * and NOT {@link DefaultIpNetAddressNameService} + {@link CachingNetAddressNameService}
     * i.e. all name service requests will fail
     * (and NOT behave, from the user perspective, as before calling this method).
     * 
     * @throws IllegalStateException    if the method call came too late after JVM start, i.e.
     *                                  class java.net.InetAddress was already initialized before
     *                                  calling this method.
     */
    public static synchronized void initNameService() throws IllegalStateException {
        // already initialized?
        if (initialized) {
            // yes: nothing to do
        } else {
            // no: initialize now
        
            // specify that the DNS will be provided by Netlib
            System.setProperty("sun.net.spi.nameservice.provider.1", "dns," + NetlibNameServiceDescriptor.DNS_PROVIDER_NAME);
    
            // disable caching as good as possible - needed to be able to switch name service implementations:
            System.setProperty("sun.net.inetaddr.ttl", "0");
            System.setProperty("sun.net.inetaddr.negative.ttl", "0");
            // in most Java/JRE environments negative.ttl cannot be changed
            // because of an higher priority of entries in file jre/lib/security/java.security:
            //    #networkaddress.cache.ttl=-1 
            //    networkaddress.cache.negative.ttl=10
            // better would be entry in file jre/lib/security/java.security: networkaddress.cache.ttl=0 and networkaddress.cache.negative.ttl=0
            // or no entry at all in this file
    
            /*
             * Currently, we do NOT specify which NetAddressNameService will be used first (class must have default constructor without arguments),
             *   Example would be: System.setProperty("org.silvertunnel.netlib.nameservice", "org.silvertunnel.netlib.nameservice.inetaddressimpl.DefaultIpNetAddressNameService");
             *
             * Instead, we omit this system property and use org.silvertunnel.netlib.nameservice.mock.NopNetAddressNameService
             */
            // update status
            initialized = true;
        }
        
        // check that java.net.InetAddress has not be initialized yet (without (Nop)NetlibNameService)
        initializedWithSuccess = isNopNetAddressNameServiceInstalled();
        if (initializedWithSuccess) {
            // success
            log.info("Installation of NameService adapter with NopNetAddressNameService was successful");
        } else {
            // error
            String msg =
                "Installation of NameService adapter with NopNetAddressNameService failed: "+
                "probably the method NameServiceGlobalUtil.initNameService() is called too late, "+
                "i.e. after first usage of java.net.InetAddress";
            log.severe(msg);
            throw new IllegalStateException(msg);
        }
    }
    
    /**
     * @return    true = installation of NameService adapter with NopNetAddressNameService was successful;
     *            false= installation was not successful
     */
    static boolean isNopNetAddressNameServiceInstalled() {
        try {
            InetAddress[] result = InetAddress.getAllByName(NopNetAddressNameService.CHECKER_NAME);
            
            // check the expected result
            if (result==null) {
                log.severe("InetAddress.getAllByName() returned null as address (but this is wrong)");
                return false;
            } else if (result.length!=1) {
                log.severe("InetAddress.getAllByName() returned array of wrong size="+result.length);
                return false;
            } else if (Arrays.equals(result[0].getAddress(), NopNetAddressNameService.CHECKER_IP[0].getIpaddress())) {
                // correct return value
                return true;
            } else {
                log.severe("InetAddress.getAllByName() returned wrong IP address="+Arrays.toString(result[0].getAddress()));
                return false;
            }
        } catch (Exception e) {
            log.severe("InetAddress.getAllByName() throwed unexpected excpetion="+e);
            return false;
        }
    }
    
    /**
     * Set a new NetAddressNameService be used as/by the java.net.InetAddress.
     * 
     * This method call influences the complete Java JVM.
     * 
     * @param lowerNetAddressNameService    the new service implementation;
     *                                      not not forget to embed it into a CachingNetAddressNameService
     *                                      (usually we want caching here to avoid performance problems)
     * @throws IllegalStateException if initSocketImplFactory() was not called before calling this method
     */
    public static synchronized void setIpNetAddressNameService(NetAddressNameService lowerNetAddressNameService) throws IllegalStateException {
        if (!initialized) {
            throw new IllegalStateException("initNameService() must be called first (but was not)");
        }
            
        // action
        NetlibNameServiceDescriptor.getSwitchingNetAddressNameService().setLowerNetAddressNameService(lowerNetAddressNameService);
    }
    
    /**
     * @return number of milliseconds to wait after a lower service switch
     *         until the new lower service is completely active
     */
    public static long getCacheTimeoutMillis() {
        return CACHE_TIMEOUT_MILLIS;
    }
}
