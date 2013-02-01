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

package org.silvertunnel.netlib.layer.tor;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetAddressNameService;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerStatus;
import org.silvertunnel.netlib.api.NetServerSocket;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.layer.control.ControlNetLayer;
import org.silvertunnel.netlib.layer.control.ControlParameters;
import org.silvertunnel.netlib.layer.tor.api.Router;
import org.silvertunnel.netlib.layer.tor.clientimpl.Tor;
import org.silvertunnel.netlib.layer.tor.common.TCPStreamProperties;
import org.silvertunnel.netlib.layer.tor.common.TorConfig;
import org.silvertunnel.netlib.layer.tor.directory.FingerprintImpl;
import org.silvertunnel.netlib.layer.tor.directory.HiddenServiceProperties;
import org.silvertunnel.netlib.layer.tor.stream.TCPStream;
import org.silvertunnel.netlib.layer.tor.util.Encoding;
import org.silvertunnel.netlib.nameservice.cache.CachingNetAddressNameService;
import org.silvertunnel.netlib.nameservice.tor.TorNetAddressNameService;
import org.silvertunnel.netlib.util.StringStorage;


/**
 * Layer over Tor network: tunnels (TCP/IP) network traffic through the Tor anonymity network.
 *  
 * @author hapke
 */
public class TorNetLayer implements NetLayer {
    private static final Logger log = Logger.getLogger(TorNetLayer.class.getName());

    /** the instance of tor used by this layer instance */
    private Tor tor;

    /**
     * the instance of NetAddressNameService;
     * will be initialized during the first call of getNetAddressNameService().
     */
    private NetAddressNameService netAddressNameService;
    
    private static final String EXIT = "exit";
    private static final Pattern EXIT_PATTERN = Pattern.compile("(.*)\\.([^\\.]+)\\."+EXIT);
    
    private NetLayer thisTorNetLayerWithTimeoutControl;
    
    static {
        try {
            /** start init of TOR (see {@link tjava.proxy.Main} */
            // load custom policy file
            // TODO webstart: Thread.currentThread().getContextClassLoader().getResource("data/TorJava.policy");
            // TODO webstart: Policy.getPolicy().refresh();
    
        } catch (Exception e) {
            log.log(Level.INFO, "problem during static construction", e);
        }
    }
    
    public TorNetLayer(NetLayer lowerTlsConnectionNetLayer, NetLayer lowerDirConnectionNetLayer, StringStorage stringStorage) throws IOException {
           // create new Tor instance
           this(new Tor(lowerTlsConnectionNetLayer, lowerDirConnectionNetLayer, stringStorage));
    }
    public TorNetLayer(Tor tor) throws IOException {
           this.tor = tor;
           
           // initialize thisTorNetLayerWithTimeoutControl,
           // use configuration parameters of Tor directory component
           ControlParameters cp = ControlParameters.createTypicalFileTransferParameters();
           cp.setConnectTimeoutMillis(TorConfig.DIR_CONNECT_TIMEOUT_MILLIS);
           cp.setOverallTimeoutMillis(TorConfig.DIR_OVERALL_TIMEOUT_MILLIS);
           cp.setInputMaxBytes(TorConfig.DIR_MAX_FILETRANSFER_BYTES);
           cp.setThroughputTimeframeMinBytes(TorConfig.DIR_THROUGPUT_TIMEFRAME_MIN_BYTES);
           cp.setThroughputTimeframeMillis(TorConfig.DIR_THROUGPUT_TIMEFRAME_MILLIS);
           thisTorNetLayerWithTimeoutControl = new ControlNetLayer(this, cp);
    }
    
    ///////////////////////////////////////////////////////
    // layer methods
    ///////////////////////////////////////////////////////

    /** @see NetLayer#createNetSocket(Map, NetAddress, NetAddress) */
    public NetSocket createNetSocket(Map<String,Object> localProperties, NetAddress localAddress, NetAddress remoteAddress) throws IOException {
        TcpipNetAddress ra = (TcpipNetAddress)remoteAddress;
        
        // create TCP stream via Tor
        TCPStreamProperties sp = convertTcpipNetAddress2TCPStreamProperties(ra);
        TCPStream remote = tor.connect(sp, thisTorNetLayerWithTimeoutControl);


        return new TorNetSocket(remote, "TorNetLayer connection to "+ra);
    }
    private TCPStreamProperties convertTcpipNetAddress2TCPStreamProperties(TcpipNetAddress ra) {
        TCPStreamProperties sp = new TCPStreamProperties(ra);
 
        // check whether a specific exit node is requested
        /*
        SYNTAX:  [hostname].[name-or-digest].exit
        [name-or-digest].exit
        Hostname is a valid hostname; [name-or-digest] is either the nickname of a
        Tor node or the hex-encoded digest of that node's public key.
        */
        String hostname = ra.getHostname();
        if (hostname!=null) {
            hostname = hostname.toLowerCase();
            Matcher m = EXIT_PATTERN.matcher(hostname);
            if (m.find()) {
                // this looks like a .exit host name: extract the parts of this special host name now
                if (log.isLoggable(Level.FINE)) {
                    log.fine("hostname with .exit pattern="+hostname);
                }
                String originalHostname = m.group(1);
                String exitNodeNameOrDigest = m.group(2);
                if (log.isLoggable(Level.FINE)) {
                    log.fine("originalHostname="+originalHostname);
                    log.fine("exitNodeNameOrDigest="+exitNodeNameOrDigest);
                }
                
                // reset the hostname
                TcpipNetAddress raNew = new TcpipNetAddress(originalHostname, ra.getPort());
                sp = new TCPStreamProperties(raNew);

                // enforce exit node
                sp.setCustomExitpoint(new FingerprintImpl(Encoding.parseHex(exitNodeNameOrDigest)));
            }
        }
 
        return sp;
    }
    
    /** @see NetLayer#createNetServerSocket(Map, NetAddress) */
    public NetServerSocket createNetServerSocket(Map<String,Object> properties, NetAddress localListenAddress) throws IOException {
        try {
            TorHiddenServicePortPrivateNetAddress netAddress = (TorHiddenServicePortPrivateNetAddress)localListenAddress;
            TorNetServerSocket torNetServerSocket = new TorNetServerSocket(netAddress.getPublicOnionHostname(), netAddress.getPort());
            
            NetLayer torNetLayerToConnectToDirectoryService = this;
            HiddenServiceProperties hiddenServiceProps = new HiddenServiceProperties(netAddress.getPort(), netAddress.getTorHiddenServicePrivateNetAddress().getKeyPair());
            tor.provideHiddenService(torNetLayerToConnectToDirectoryService, hiddenServiceProps, torNetServerSocket);

            return torNetServerSocket;
            
        } catch (Exception e) {
            String msg = "could not create NetServerSocket for localListenAddress="+localListenAddress;
            log.log(Level.SEVERE, "could not create NetServerSocket", e);
            throw new IOException(msg);
        }
    }
 
    /** @see NetLayer#getStatus() */
    public NetLayerStatus getStatus() {
        return tor.getStatus();
    }
   
    /**
     * Wait (block the current thread) until the Tor net layer is up and ready or a configured timeout comes up.
     * 
     * @see ExtendedNetLayer#waitUntilReady()
     */
    public void waitUntilReady() {
        tor.checkStartup();
    }

    /** @see NetLayer#clear() */
    public void clear() throws IOException {
        log.info("clear() started");
        tor.clear();
        log.info("clear() finished");
    }
    
    /**
     * @see ExtendedNetLayer#getNetAddressNameService()
     * 
     * @return a TorNetAddressNameService instance
     */
    public NetAddressNameService getNetAddressNameService() {
        if (netAddressNameService==null) {
            // create a new instance
            netAddressNameService = new CachingNetAddressNameService(new TorNetAddressNameService(tor) {
                // use this anonymous class to access the protected constructor
            });
        }
        
        return netAddressNameService;
    }
    
    
    ///////////////////////////////////////////////////////
    // layer specific methods
    ///////////////////////////////////////////////////////
    
    /**
     * @return read-only view of the currently valid Tor routers
     */
    public Collection<Router> getValidTorRouters() {
        waitUntilReady();
        return tor.getValidTorRouters();
    }
}
