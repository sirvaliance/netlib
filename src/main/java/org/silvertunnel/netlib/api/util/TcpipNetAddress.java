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

package org.silvertunnel.netlib.api.util;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.silvertunnel.netlib.api.NetAddress;


/**
 * IP address or host name plus TCP port number.
 * 
 * Used by TcpipNetLayer.
 *  
 * @author hapke
 */
public class TcpipNetAddress implements NetAddress {
    private static final Logger log = Logger.getLogger(TcpipNetAddress.class.getName());
    
    private String hostname;
    /** 4 bytes for IPv4 or 16bytes for IPv6 */
    private byte[] ipaddress;
    private int port;
    
    private static final String DEFAULT_HOSTNAME = "0.0.0.0";
    private static final int MIN_PORT = 0;
    private static final int MAX_PORT = 65535;

    /** pattern of IP4 address */
    private static Pattern ip4Pattern;

    /**
     * Initialize in a way that exceptions get logged.
     */
    static {
        try {
            ip4Pattern = Pattern.compile("(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)",
                    Pattern.DOTALL + Pattern.CASE_INSENSITIVE + Pattern.UNIX_LINES);
        } catch (Exception e) {
            log.log(Level.SEVERE, "could not initialze class AuthorityKeyCertificate", e);
        }
    }
    
    /**
     * Create a new object based on a String. The String has the same format as the address/port of a URL.
     * TODO: specify RFC or other format standard document.
     * 
     * The port part is mandatory.
     * The address/name part is optional with default "0.0.0.0".
     * 
     * Examples:
     * 80 -> IPv4 address 0.0.0.0 and port 80
     * 127.0.0.1:80 -> IPv4 address 127.0.0.1 and port 80
     * [::1/128]:80 -> IPv6 address ::1/128 and port 80 (not yet implemented)
     * 
     * @param hostnameOrIpaddressAndTcpPort    String to interpret
     * @throws IllegalArgumentException if the argument could not be parsed or is invalid
     */
    public TcpipNetAddress(String hostnameOrIpaddressAndTcpPort) throws IllegalArgumentException {
        String portStr;
        if (hostnameOrIpaddressAndTcpPort.contains(":")) {
            // with address + port:
            // extract hostname
            int idx = hostnameOrIpaddressAndTcpPort.lastIndexOf(':');
            hostname = hostnameOrIpaddressAndTcpPort.substring(0, idx);
            if (hostname.length()==0) {
                hostname = DEFAULT_HOSTNAME;
            }
            
            // is it a IPv4 address?
            try {
                Matcher m = ip4Pattern.matcher(hostname);
                if (m.find()) {
                    ipaddress = new byte[4];
                    for (int i=0; i<4; i++) {
                        ipaddress[i] = (byte)Integer.parseInt(m.group(i+1)); 
                    }
                }
            } catch (Exception e) {
                throw new IllegalArgumentException("could not parse IPv4 address="+hostname);
            }
            
            // extract port
            portStr = hostnameOrIpaddressAndTcpPort.substring(idx+1);
        } else {
            // with port only
            hostname = DEFAULT_HOSTNAME;
            portStr = hostnameOrIpaddressAndTcpPort;
        }

        // finalize port
        try {
            port = Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("port could not be parsed of nameOrIpAddressAndTcpPort="+hostnameOrIpaddressAndTcpPort);
        }
        checkThis();
    }
    
    /**
     * Create a new object.
     * 
     * @param hostname
     * @param port
     */
    public TcpipNetAddress(String hostname, int port) {
        this.hostname = hostname;
        this.port = port;
    }
    
    /**
     * Create a new object.
     * 
     * @param ipaddress    4 bytes for IPv4 or 16 bytes for IPv6
     * @param port
     * @throws IllegalArgumentException if the argument could not be parsed or is invalid
     */
    public TcpipNetAddress(byte[] ipaddress, int port) throws IllegalArgumentException {
        if (ipaddress!=null) {
            if (ipaddress.length==4) {
                // IPv4
                this.ipaddress = ipaddress;
            } else if (ipaddress.length==16) {
                // IPv6
                this.ipaddress = ipaddress;
            } else {
                throw new IllegalArgumentException("invalid IP address length ("+ipaddress.length+" bytes )");
            }
        }
        this.port = port;
    }

    /**
     * Create a new object.
     * 
     * @param ipaddress    4 bytes for IPv4 or 16 bytes for IPv6
     * @param port
     * @throws IllegalArgumentException if the argument could not be parsed or is invalid
     */
    public TcpipNetAddress(IpNetAddress ipaddress, int port) throws IllegalArgumentException {
        this(ipaddress.getIpaddress(), port);
    }

    /**
     * Create a new object.
     * 
     * @param hostname
     * @param ipaddress    4 bytes for IPv4 or 16 bytes for IPv6
     * @param port
     * @throws IllegalArgumentException if the argument could not be parsed or is invalid
     */
    public TcpipNetAddress(String hostname, byte[] ipaddress, int port) throws IllegalArgumentException {
        this.hostname = hostname;
        if (ipaddress!=null) {
            if (ipaddress.length==4) {
                // IPv4
                this.ipaddress = ipaddress;
            } else if (ipaddress.length==16) {
                // IPv6
                this.ipaddress = ipaddress;
            } else {
                throw new IllegalArgumentException("invalid IP address length ("+ipaddress.length+" bytes )");
            }
        }
        this.port = port;
    }
 
    /**
     * Create a new object.
     * 
     * @param hostname
     * @param ipaddress    4 bytes for IPv4 or 16 bytes for IPv6
     * @param port
     * @throws IllegalArgumentException if the argument could not be parsed or is invalid
     */
    public TcpipNetAddress(String hostname, InetAddress inetAddress, int port) throws IllegalArgumentException {
        this.hostname = hostname;
        if (inetAddress!=null) {
            if (inetAddress instanceof Inet4Address) {
                // IPv4
                this.ipaddress = ((Inet4Address)inetAddress).getAddress();
            } else if (ipaddress.length==16) {
                // IPv6
                this.ipaddress = ((Inet6Address)inetAddress).getAddress();
            } else {
                throw new IllegalArgumentException("invalid inet address="+inetAddress);
            }
        }
        this.port = port;
    }

    /**
     * Create a new object.
     * 
     * @param inetAddress    4 bytes for IPv4 or 16 bytes for IPv6
     * @param port
     * @throws IllegalArgumentException if the argument could not be parsed or is invalid
     */
    public TcpipNetAddress(InetAddress inetAddress, int port) throws IllegalArgumentException {
        if (inetAddress!=null) {
            if (inetAddress instanceof Inet4Address) {
                // IPv4
                this.ipaddress = ((Inet4Address)inetAddress).getAddress();
            } else if (ipaddress.length==16) {
                // IPv6
                this.ipaddress = ((Inet6Address)inetAddress).getAddress();
            } else {
                throw new IllegalArgumentException("invalid inet address="+inetAddress);
            }
        }
        this.port = port;
    }

    /**
     * Called form constructor.
     * 
     * @throws IllegalArgumentException
     */
    private void checkThis() throws IllegalArgumentException {
        if (port<MIN_PORT || port > MAX_PORT) {
            throw new IllegalArgumentException("port="+port+" is out of range");
        }
    }
    
    public String getHostname() {
        return hostname;
    }

    /**
     * @return something like "localhost:80"
     */
    public String getHostnameAndPort() {
    	String hostname = this.hostname;
    	hostname = (hostname==null) ? "" : hostname;
    	return hostname+":"+port;
    	
    }
    
    public byte[] getIpaddress() {
        return ipaddress;
    }

    public IpNetAddress getIpNetAddress() {
        return new IpNetAddress(ipaddress);
    }

    public String getIpaddressAsString() {
        if (ipaddress==null) {
            return null;
        } else if (ipaddress.length==4) {
            // IPv4
            return
                getByteAsNonnegativeInt(ipaddress[0])+"."+
                getByteAsNonnegativeInt(ipaddress[1])+"."+
                getByteAsNonnegativeInt(ipaddress[2])+"."+
                getByteAsNonnegativeInt(ipaddress[3]);
        } else {
            // IPv6
            StringBuffer result = new StringBuffer();
            // TODO:
            return ":IPv6:"+ipaddress;
        }
    }
    private int getByteAsNonnegativeInt(byte b) {
        if (b>=0) {
            return b;
        } else {
            return 256+b;
        }
    }

    /**
     * @return something like "127.0.0.1:80"
     */
    public String getIpaddressAndPort() {
    	String ipaddress = getIpaddressAsString();
    	ipaddress = (ipaddress==null) ? "" : ipaddress;
    	return ipaddress+":"+port;
    	
    }

    public InetAddress getIpaddressAsInetAddress() {
        if (ipaddress==null) {
            // no address set
            return null;
            
        } else {
            // address set
            try {
                return InetAddress.getByAddress(ipaddress);
            } catch (UnknownHostException e) {
                log.log(Level.WARNING, "could not convert into InetAddress: "+toString(), e);
                return null;
            }
        }
    }
    
    /**
     * @return the host name;
     *         if it is not set then the method returns the IP address
     *         in dotted notation
     */
    public String getHostnameOrIpaddress() {
        if (hostname!=null) {
            return hostname;
        } else {
            return getIpaddressAsString();
        }
    }
    
    public int getPort() {
        return port;
    }
    
    /**
     * @return a unique id
     */
    protected String getId() {
        return "TcpipNetAddress(hostname="+hostname+",ipaddress="+getIpaddressAsString()+",port="+port+")";
    }
    
    @Override
    public String toString() {
        return getId();
    }
    
    @Override
    public int hashCode() {
        return getId().hashCode();
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj==null || !(obj instanceof TcpipNetAddress)) {
            return false;
        }
        
        TcpipNetAddress other = (TcpipNetAddress)obj;
        return getId().equals(other.getId());
    }
}
