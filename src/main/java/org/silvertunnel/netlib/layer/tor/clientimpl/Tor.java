/*
 * OnionCoffee - Anonymous Communication through TOR Network
 * Copyright (C) 2005-2007 RWTH Aachen University, Informatik IV
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */
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

package org.silvertunnel.netlib.layer.tor.clientimpl;

import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerStatus;
import org.silvertunnel.netlib.api.util.IpNetAddress;
import org.silvertunnel.netlib.layer.tor.api.Router;
import org.silvertunnel.netlib.layer.tor.api.TorNetLayerStatus;
import org.silvertunnel.netlib.layer.tor.circuit.Circuit;
import org.silvertunnel.netlib.layer.tor.circuit.CircuitAdmin;
import org.silvertunnel.netlib.layer.tor.circuit.CircuitsStatus;
import org.silvertunnel.netlib.layer.tor.circuit.HiddenServicePortInstance;
import org.silvertunnel.netlib.layer.tor.circuit.TLSConnection;
import org.silvertunnel.netlib.layer.tor.circuit.TLSConnectionAdmin;
import org.silvertunnel.netlib.layer.tor.common.TCPStreamProperties;
import org.silvertunnel.netlib.layer.tor.common.TorConfig;
import org.silvertunnel.netlib.layer.tor.common.TorEventService;
import org.silvertunnel.netlib.layer.tor.directory.Directory;
import org.silvertunnel.netlib.layer.tor.directory.HiddenServiceProperties;
import org.silvertunnel.netlib.layer.tor.directory.RouterImpl;
import org.silvertunnel.netlib.layer.tor.stream.ClosingThread;
import org.silvertunnel.netlib.layer.tor.stream.ResolveStream;
import org.silvertunnel.netlib.layer.tor.stream.StreamThread;
import org.silvertunnel.netlib.layer.tor.stream.TCPStream;
import org.silvertunnel.netlib.layer.tor.util.NetLayerStatusAdmin;
import org.silvertunnel.netlib.layer.tor.util.PrivateKeyHandler;
import org.silvertunnel.netlib.layer.tor.util.TorException;
import org.silvertunnel.netlib.layer.tor.util.TorNoAnswerException;
import org.silvertunnel.netlib.util.StringStorage;

/**
 * MAIN CLASS. keeps track of circuits, tls-connections and the status of
 * servers. Provides high level access to all needed functionality, i.e.
 * connecting to some remote service via Tor.
 * 
 * @author Lexi Pimenidis
 * @author Tobias Koelsch
 * @author Vinh Pham
 * @author Andriy Panchenko
 * @author Michael Koellejan
 * @author hapke
 */
public class Tor implements NetLayerStatusAdmin {
    private static final Logger log = Logger.getLogger(Tor.class.getName());

    private static final int TOR_CONNECT_MAX_RETRIES = 10;
    private static final long TOR_CONNECT_MILLICESCONDS_BETWEEN_RETRIES = 10;
    
    private Directory directory;
    private TLSConnectionAdmin tlsConnectionAdmin;
    private TorBackgroundMgmtThread torBackgroundMgmtThread;
    private TorConfig torConfig;
    private PrivateKeyHandler privateKeyHandler;
    /**
     * Absolute time in milliseconds: until this date/time the init is in progress.
     * 
     * Used to delay connects until Tor has some time to build up circuits and stuff.
     */
    private long startupPhaseWithoutConnects; 

    /** lower layer network layer, e.g. TLS over TCP/IP to connect to TOR onion routers */
    private NetLayer lowerTlsConnectionNetLayer;
    /** lower layer network layer, e.g. TCP/IP to connect to directory servers */
    private NetLayer lowerDirConnectionNetLayer;
    /** storage that can be used, e.g. to cache directory information */
    private StringStorage stringStorage;
    private TorEventService torEventService = new TorEventService();
    
    private boolean gaveMessage = false;
    private boolean startUpInProgress = true;

    private NetLayerStatus status = TorNetLayerStatus.NEW;
    
    /**
     * Initialize Tor with all defaults
     * 
     * @exception IOException
     */
    public Tor(NetLayer lowerTlsConnectionNetLayer, NetLayer lowerDirConnectionNetLayer, StringStorage stringStorage) throws IOException {
        this.lowerTlsConnectionNetLayer = lowerTlsConnectionNetLayer;
        this.lowerDirConnectionNetLayer = lowerDirConnectionNetLayer;
        this.stringStorage = stringStorage;
        // TODO webstart: config = new TorConfig(true);
        torConfig = new TorConfig(false);
        initLocalSystem(false);
        initDirectory();
        initRemoteAccess();
    }


    private void initLocalSystem(boolean noLocalFileSystemAccess) throws IOException {
        // install BC, if not already done
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            // Security.insertProviderAt(new
            // org.bouncycastle.jce.provider.BouncyCastleProvider(),2);
        }
        // logger and config
        log.info("Tor implementation of silvertunnel.org is starting up");
        // create identity
        privateKeyHandler = new PrivateKeyHandler();
        // determine end of startup-Phase
        startupPhaseWithoutConnects = System.currentTimeMillis() + TorConfig.startupDelaySeconds * 1000L;
        // init event-handler
    }

    private void initDirectory() throws IOException {
        directory = new Directory(torConfig, stringStorage, lowerDirConnectionNetLayer, privateKeyHandler.getIdentity(), this);
    }

    private void initRemoteAccess() throws IOException {
        // establish handler for TLS connections
        tlsConnectionAdmin = new TLSConnectionAdmin(lowerTlsConnectionNetLayer, privateKeyHandler);
        // initialize thread to renew every now and then
        torBackgroundMgmtThread = new TorBackgroundMgmtThread(this, TorConfig.defaultIdleCircuits);
         // directory service
        if (TorConfig.dirserverPort > 0) {
            // TODO: dirserver = new DirectoryServer(dir, TorConfig.dirserverPort)
        }
    }
    
    /**
     * @return read-only view of the currently valid Tor routers
     */
    public Collection<Router> getValidTorRouters() {
        Collection<RouterImpl> resultBase = directory.getValidRoutersByFingerprint().values();
        Collection<Router> result = new ArrayList<Router>(resultBase.size());

        // copy all routers to the result collection
        for (RouterImpl r : resultBase) {
               result.add(r.cloneReliable());
        }
        
        return result;
    }
         
    /**
     * makes a connection to a remote service
     * 
     * @param sp
     *            hostname, port to connect to and other stuff
     * @return some socket-thing
     */
    public TCPStream connect(TCPStreamProperties sp, NetLayer torNetLayer) throws IOException {
        if (sp.getHostname()==null && sp.getAddr()==null) {
            throw new IOException("Tor: no hostname and no address provided");
        }

        // check, if tor is still in startup-phase
        checkStartup();
                
        // check whether the address is hidden
        if (sp.getHostname()!=null && sp.getHostname().endsWith(".onion")) {
            return HiddenServiceClient.connectToHiddenService(torConfig, directory, torEventService, tlsConnectionAdmin, torNetLayer, sp);
        }
        
        // connect to exit server
        int retry=0;
        String hostnameAddress = null;
        for (; retry<=TOR_CONNECT_MAX_RETRIES; retry++) {
            // check precondition
            final int MIN_IDLE_CIRCUITS = Math.min(2, TorConfig.minimumIdleCircuits);
            waitForIdleCircuits(MIN_IDLE_CIRCUITS);
            
            // action
            Circuit[] cs = CircuitAdmin.provideSuitableCircuits(tlsConnectionAdmin, directory, sp, torEventService, false);
            if (cs==null || cs.length<1) {
                // no valid circuit found: wait for new one created by the TorBackgroundMgmtThread
                try {
                    Thread.sleep(TorBackgroundMgmtThread.INTERVAL_S*1000L);
                } catch (InterruptedException e) { }
                continue;
            }
            if (TorConfig.veryAggressiveStreamBuilding) {
    
                for (int j = 0; j < cs.length; ++j) {
                    // start N asynchronous stream building threads
                    try {
                        StreamThread[] streamThreads = new StreamThread[cs.length];
                        for (int i = 0; i < cs.length; ++i)
                            streamThreads[i] = new StreamThread(cs[i], sp);
                        // wait for the first stream to return
                        int chosenStream = -1;
                        int waitingCounter = TorConfig.queueTimeoutStreamBuildup * 1000 / 10;
                        while ((chosenStream < 0) && (waitingCounter >= 0)) {
                            boolean atLeastOneAlive = false;
                            for (int i = 0; (i < cs.length) && (chosenStream < 0); ++i)
                                if (!streamThreads[i].isAlive()) {
                                    if ((streamThreads[i].getStream() != null) && (streamThreads[i].getStream().isEstablished())) {
                                        chosenStream = i;
                                    }
                                } else {
                                    atLeastOneAlive = true;
                                }
                            if (!atLeastOneAlive)
                                break;
    
                            final long SLEEPING_MS = 10;
                            try {
                                Thread.sleep(SLEEPING_MS);
                            } catch (InterruptedException e) {
                            }
    
                            --waitingCounter;
                        }
                        // return one and close others
                        if (chosenStream >= 0) {
                            TCPStream returnValue = streamThreads[chosenStream].getStream();
                            new ClosingThread(streamThreads, chosenStream);
                            return returnValue;
                        }
                    } catch (Exception e) {
                        log.warning("Tor.connect(): " + e.getMessage());
                        return null;
                    }
                }
    
            } else {
                // build serial N streams, stop if successful
                for (int i = 0; i < cs.length; ++i) {
                    try {
                        return new TCPStream(cs[i], sp);
                    } catch (TorNoAnswerException e) {
                        log.warning("Tor.connect: Timeout on circuit:" + e.getMessage());
                    } catch (TorException e) {
                        log.warning("Tor.connect: TorException trying to reuse existing circuit:" + e.getMessage());
                    } catch (IOException e) {
                        log.warning("Tor.connect: IOException " + e.getMessage());
                    }
                }
            }
    
            hostnameAddress = (sp.getAddr() != null) ? "" + sp.getAddr() : sp.getHostname();
            log.info("Tor.connect: not (yet) connected to " + hostnameAddress + ":" + sp.getPort() + ", full retry count="+retry);
            try {
                Thread.sleep(TOR_CONNECT_MILLICESCONDS_BETWEEN_RETRIES);
            } catch (InterruptedException e) {}
        }
        throw new IOException("Tor.connect: unable to connect to " + hostnameAddress + ":" + sp.getPort() + " after "+retry+" full retries with "+ sp.getConnectRetries() + " sub retries");
    }

    
    /**
     * initializes a new hidden service
     * 
     * @param service
     *            all data needed to init the things
     */
    public void provideHiddenService(NetLayer torNetLayerToConnectToDirectoryService, HiddenServiceProperties service, HiddenServicePortInstance hiddenServicePortInstance)
            throws IOException, TorException {
        // check, if tor is still in startup-phase
        checkStartup();
        
        // action
        HiddenServiceServer.getInstance().provideHiddenService(
                torConfig, directory, torEventService, tlsConnectionAdmin, torNetLayerToConnectToDirectoryService, service, hiddenServicePortInstance);
    }


    /**
     * shut down everything
     * 
     * @param force
     *            set to true, if everything shall go fast. For graceful end,
     *            set to false
     */
    public void close(boolean force) {
        log.info("TorJava ist closing down");
        // shutdown mgmt
        torBackgroundMgmtThread.close();
        // shut down connections
        tlsConnectionAdmin.close(force);
        // shutdown directory
        directory.close();
        // write config file 
        torConfig.close();
        // close hidden services
        // TODO close hidden services
        // kill logger
        log.info("Tor.close(): CLOSED");
    }

    /** synonym for close(false); */
    public void close() {
        close(false);
    }

    /**
     * Anonymously resolve a host name.
     * 
     * @param name    the host name
     * @return the resolved IP; null if no mapping found
     */
    public IpNetAddress resolve(String hostname) throws IOException {
        Object o = resolveInternal(hostname);
        if (o instanceof IpNetAddress) {
            return (IpNetAddress) o;
        } else {
            return null;
        }
    }

    /**
     * Anonymously do a reverse look-up
     * 
     * @param addr    the IP address to be resolved
     * @return the host name; null if no mapping found
     */
    public String resolve(IpNetAddress addr) throws IOException {
        // build address (works only for IPv4!)
        byte[] a = addr.getIpaddress();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 4; ++i) {
            sb.append((int) (a[3 - i]) & 0xff);
            sb.append('.');
        }
        sb.append("in-addr.arpa");
        // resolve address
        Object o = resolveInternal(sb.toString());
        if (o instanceof String) {
            return (String) o;
        } else {
            return null;
        }
    }

    /**
     * internal function to use the tor-resolve-functionality
     * 
     * @param query
     *            a hostname to be resolved,
     *            or for a reverse lookup: A.B.C.D.in-addr.arpa
     * @return either an IpNetAddress (normal query),
     *            or a String (reverse-DNS-lookup)
     */
    private Object resolveInternal(String query) throws IOException {
        try {
            // check, if tor is still in startup-phase
            checkStartup();
            // try to resolve query over all existing circuits
            // so iterate over all TLS-Connections
            for (TLSConnection tls : tlsConnectionAdmin.getConnections()) {
                // and over all circuits in each TLS-Connection
                for (Circuit circuit : tls.getCircuits()) {
                    try {
                        if (circuit.isEstablished()) {
                            // if an answer is given, we're satisfied
                            ResolveStream rs = new ResolveStream(circuit);
                            Object o = rs.resolve(query);
                            rs.close();
                            return o;
                        }
                    } catch (Exception e) {
                        // in case of error, do nothing, but retry with the next
                        // circuit
                    }
                }
            }
            // if no circuit could give an answer (possibly there was no
            // established circuit?)
            // build a new circuit and ask this one to resolve the query
            ResolveStream rs = new ResolveStream(new Circuit(tlsConnectionAdmin, directory, new TCPStreamProperties(), torEventService));
            Object o = rs.resolve(query);
            rs.close();
            return o;
        } catch (TorException e) {
            throw new IOException("Error in Tor: " + e.getMessage());
        } catch (InterruptedException e) {
            throw new IOException("Error in Tor: " + e.getMessage());
        }
    }

    public void setStatus(NetLayerStatus newStatus) {
        log.fine("TorNetLayer old status: "+status);
        status = newStatus;
        log.info("TorNetLayer new status: "+status);
    }
    /**
     * Set the new status, but only,
     * if the new readyIndicator is higher than the current one.
     *  
     * @param newStatus
     */
    public void updateStatus(NetLayerStatus newStatus) {
        if (getStatus().getReadyIndicator()<newStatus.getReadyIndicator()) {
            setStatus(newStatus);
        }
    }
    public NetLayerStatus getStatus() {
        return status;
    }
    
    /**
     * make sure that tor had some time to read the directory and build up some
     * circuits
     */
    public void checkStartup() {
        // start up is proved to be over
        if (!startUpInProgress)
            return;

        // check if startup is over
        long now = System.currentTimeMillis();
        if (now >= startupPhaseWithoutConnects) {
            startUpInProgress = false;
            return;
        }

        // wait for startup to be over
        long sleep = startupPhaseWithoutConnects - System.currentTimeMillis();
        if (!gaveMessage) {
            gaveMessage = true;
            log.fine("Tor.checkStartup(): Tor is still in startup phase, sleeping for max. " + (sleep / 1000L) + " seconds");
            log.fine("Tor not yet started - wait until torServers available");
        }
        // try { Thread.sleep(sleep); }
        // catch(Exception e) {}

        // wait until server info and established circuits are available
        waitForIdleCircuits(TorConfig.minimumIdleCircuits);
        try {
            Thread.sleep(2000);
        } catch (Exception e) { /* ignore it */ }
        log.info("Tor start completed!!!");
        startUpInProgress = false;
    }
    
    /**
     * Wait until Tor has at least minExpectedIdleCircuits idle circuits.
     * 
     * @param minExpectedIdleCircuits
     */
    private void waitForIdleCircuits(int minExpectedIdleCircuits) {
        // wait until server info and established circuits are available
        while (!directory.isDirectoryReady() || getCircuitsStatus().getCircuitsEstablished() < minExpectedIdleCircuits) {
            try {
                Thread.sleep(100);
            } catch (Exception e) { /* ignore it */ }
        }
    }

    /**
     * returns a set of current established circuits (only used by
     * TorJava.Proxy.MainWindow to get a list of circuits to display)
     * 
     */
    public HashSet<Circuit> getCurrentCircuits() {

        HashSet<Circuit> allCircs = new HashSet<Circuit>();
        for (TLSConnection tls : tlsConnectionAdmin.getConnections()) {
            for (Circuit circuit : tls.getCircuits()) {
                // if (circuit.established && (!circuit.closed)){
                allCircs.add(circuit);
                // }
            }
        }
        return allCircs;
    }

    /**
     * @return status summary of the Ciruits
     */
    public CircuitsStatus getCircuitsStatus()  {
        // count circuits
        int circuitsTotal = 0; // all circuits
        int circuitsAlive = 0; // circuits that are building up, or that are established
        int circuitsEstablished = 0; // established, but not already closed
        int circuitsClosed = 0; // closing down
        
        for (TLSConnection tls : tlsConnectionAdmin.getConnections()) {
            for (Circuit c : tls.getCircuits()) {
                String flag = "";
                ++circuitsTotal;
                if (c.isClosed()) {
                    flag = "C";
                    ++circuitsClosed;
                } else {
                    flag = "B";
                    ++circuitsAlive;
                    if (c.isEstablished()) {
                        flag = "E";
                        ++circuitsEstablished;
                    }
                }
                if (log.isLoggable(Level.FINER)) {
                    log.finer("Tor.getCircuitsStatus(): " + flag + " rank " + c.getRanking() + " fails " + c.getStreamFails() + " of " + c.getStreamCounter() + " TLS "
                            + tls.getRouter().getNickname() + "/" + c.toString());
                }
            }
        }
        
        CircuitsStatus result = new CircuitsStatus();
        result.setCircuitsTotal(circuitsTotal);
        result.setCircuitsAlive(circuitsAlive);
        result.setCircuitsEstablished(circuitsEstablished);
        result.setCircuitsClosed(circuitsClosed);
        
        return result;
    }
    /**
     * Remove the current history.
     * Close all circuits that were already be used.
     */
    public void clear() {
        CircuitAdmin.clear(tlsConnectionAdmin);
    }

    ///////////////////////////////////////////////////////
    // getters and setters
    ///////////////////////////////////////////////////////
    
    public TorEventService getTorEventService() {
        return torEventService;
    }

    public Directory getDirectory() {
        return directory;
    }

    public TLSConnectionAdmin getTlsConnectionAdmin() {
        return tlsConnectionAdmin;
    }

    public TorConfig getTorConfig() {
        return torConfig;
    }

    public NetLayer getLowerTlsConnectionNetLayer() {
        return lowerTlsConnectionNetLayer;
    }

    public NetLayer getLowerDirConnectionNetLayer() {
        return lowerDirConnectionNetLayer;
    }

    public PrivateKeyHandler getPrivateKeyHandler() {
        return privateKeyHandler;
    } 
}
