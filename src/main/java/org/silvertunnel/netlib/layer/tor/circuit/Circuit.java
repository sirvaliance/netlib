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
package org.silvertunnel.netlib.layer.tor.circuit;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.layer.tor.api.Fingerprint;
import org.silvertunnel.netlib.layer.tor.api.Router;
import org.silvertunnel.netlib.layer.tor.common.TCPStreamProperties;
import org.silvertunnel.netlib.layer.tor.common.TorConfig;
import org.silvertunnel.netlib.layer.tor.common.TorEvent;
import org.silvertunnel.netlib.layer.tor.common.TorEventService;
import org.silvertunnel.netlib.layer.tor.directory.Directory;
import org.silvertunnel.netlib.layer.tor.directory.HiddenServiceProperties;
import org.silvertunnel.netlib.layer.tor.directory.RendezvousServiceDescriptor;
import org.silvertunnel.netlib.layer.tor.directory.RouterImpl;
import org.silvertunnel.netlib.layer.tor.util.Encoding;
import org.silvertunnel.netlib.layer.tor.util.Encryption;
import org.silvertunnel.netlib.layer.tor.util.TorException;
import org.silvertunnel.netlib.util.ByteArrayUtil;


/**
 * handles the functionality of creating circuits, given a certain route and
 * buidling tcp-streams on top of them.
 * 
 * @author Lexi Pimenidis
 * @author Tobias Koelsch
 * @author Andriy Panchenko
 * @author Michael Koellejan
 * @author hapke
 */
public class Circuit {
    private static final Logger log = Logger.getLogger(Circuit.class.getName());

    final int circuitLevelFlowControl = 1000;
    final int circuitLevelFlowControlIncrement = 100;
    
    /**  */
    public static volatile int numberOfCircuitsInConstructor = 0;
    /** a pointer to the TLS-layer */
    private TLSConnection tls;
    /** stores the route */
    private Node[] routeNodes;
    /** number of nodes in the route, where the keys have been established */
    private int routeEstablished;
    /** used to receive incoming data */
    private Queue queue;
    /**
     * list of all TCP-streams relayed through this circuit
     * 
     * key=stream ID, value=stream
     */
    private Map<Integer, Stream> streams = Collections.synchronizedMap(new HashMap<Integer,Stream>()); 
    /**
     * contains URLs, InetAddresse or z-part of HS URL of hosts
     * used to make contact to (or for DNS query) with this Circuit
     */
    private HashSet<Object> streamHistory = new HashSet<Object>();
    /** counts the number of established streams */                      
    private int establishedStreams = 0;
    /** service descriptor in case if used for rendezvous pint */
    private RendezvousServiceDescriptor serviceDescriptor; 
    /** ID */
    private int id;
    /** set to true, if route is established */
    private boolean established;
    /** set to true, if no new streams are allowed */
    private boolean closed;
    /** set to true, if circuit is closed and inactive and may be removed from all sets */
    private boolean destruct;
    /**  */
    private Date created;
    /** last time, a cell was send that was not a padding cell */
    private Date lastAction;
    /** last time, a cell was send */
    private Date lastCell; // 
    /** time in milliseconds it took to establish the circuit */
    private int setupDurationMs;
    /** ranking index of the circuit */
    private int ranking;
    /** duration of all streams' setup times  */
    private int sumStreamsSetupDelays;
    /** overall number of streams relayed through the circuit */
    private int streamCounter;
    /** overall counter of failures in streams in this circuit */
    private int streamFails;

    QueueFlowControlHandler queueFlowControlHandler;
    Directory directory;
    TLSConnectionAdmin tlsConnectionAdmin;
    private TorEventService torEventService;
    
    private boolean closeCircuitIfLastStreamIsClosed;

    /**
     * This circuit is used for (server side) hidden service introduction,
     * this field saved the corresponding HiddenServiceInstance.
     */
    private HiddenServiceInstance hiddenServiceInstanceForIntroduction;

    /**
     * This circuit is used for (server side) hidden service rendezvous,
     * this field saved the corresponding HiddenServiceInstance.
     */
    private HiddenServiceInstance hiddenServiceInstanceForRendezvous;
    

    
    /**
     * initiates a circuit. tries to rebuild the circuit for a limited number of
     * times, if first attempt fails.
     * 
     * @param fnh
     *            a pointer to the TLS-Connection to the first node
     * @param dir
     *            a pointer to the directory, in case an alternative route is
     *            necessary
     * @param sp
     *            some properties for the stream that is the reason for building
     *            the circuit (needed if the circuit is needed to ask the
     *            directory for a new route)
     * 
     * @exception TorException
     * @exception IOException
     */
    public Circuit(TLSConnectionAdmin fnh, Directory dir, TCPStreamProperties sp, TorEventService torEventService)
            throws IOException, TorException, InterruptedException  {
        numberOfCircuitsInConstructor++;
        boolean successful = false;
        try {
            // init variables
            this.directory = dir;
            this.tlsConnectionAdmin = fnh;
            this.torEventService = torEventService;
            closed = false;
            established = false;
            destruct = false;
            sumStreamsSetupDelays = 0;
            streamCounter = 0;
            streamFails = 0;
            ranking = -1; // unused circs have highest priority for selection
            created = new Date();
            lastAction = created;
            lastCell = created;
            
            // save original Thread name
            Thread currentThread = Thread.currentThread();
            String originalThreadName = currentThread.getName();
            
            // get a new route
            RouterImpl[] routeServers = CircuitAdmin.createNewRoute(dir, sp);
            if (routeServers==null || routeServers.length<1) throw new TorException("Circuit: could not build route");
            // try to build a circuit
            long startSetupTime = System.currentTimeMillis();
            for (int misses = 1;; ++misses) {
                long currentSetupDuration = System.currentTimeMillis() - startSetupTime;
                if (currentSetupDuration>=TorConfig.maxAllowedSetupDurationMs) {
                    // stop here because it cannot be successful any more
                    String msg = "Circuit: close-during-create " + toString() + ", because current duration of " + currentSetupDuration + " ms is already too long";
                    log.info(msg);
                    throw new IOException(msg);
                }
                
                // set thread name
                if (originalThreadName!=null && originalThreadName.startsWith("Idle Thread")) { 
                    currentThread.setName(originalThreadName+" - Circuit to "+routeServers[routeServers.length-1].getNickname());
                }
                
                if (Thread.interrupted()) {
                    throw new InterruptedException();
                }
                try {
                    // attach circuit to TLS
                    log.fine("Circuit: connecting to " + routeServers[0].getNickname() + " (" + routeServers[0].getCountryCode() +  ") over tls");
                    tls = fnh.getConnection(routeServers[0]);
                    queue = new Queue(TorConfig.queueTimeoutCircuit);
                    // attention: Addition to circuits-list is quite hidden here.
                    id = tls.assignCircuitId(this);
                    routeEstablished = 0;
                    // connect to entry point = routeServers[0]
                    log.fine("Circuit: sending create cell to " + routeServers[0].getNickname());
                    routeNodes = new Node[routeServers.length];
                    create(routeServers[0]);
                    routeEstablished = 1;
                    // extend route
                    for (int i = 1; i < routeServers.length; ++i) {
                        log.fine("Circuit: " + toString() + " extending to " + routeServers[i].getNickname() + " (" + routeServers[i].getCountryCode() + ")");
                        extend(i, routeServers[i]);
                        routeEstablished += 1;
                    }
                    // finished - success
                    break;

                } catch (Exception e) {
                    // some error occurred during the creating of the circuit
                    log.fine("Circuit: " + toString() + " Exception " + misses + " :" + e);
                    // cleanup now
                    if (id!=0) {
                        tls.removeCircuit(id);
                    }
                    // error handling
                    if (closed) {
                        throw new IOException("Circuit: " + toString() + " closing during buildup");
                    }
                    if (misses >= TorConfig.reconnectCircuit) {
                        // enough retries, exit
                        if (e instanceof IOException) { 
                            throw (IOException)e; 
                        } else if (e instanceof IOException) { 
                            throw (TorException)e; 
                        } else {
                            throw new TorException(e.toString());
                        }
                    }
                    // build a new route over the hosts that are known to be
                    // working, punish failing host
                    routeServers = CircuitAdmin.restoreCircuit(dir, sp, routeServers, routeEstablished);
                }
            }
            setupDurationMs = (int) (System.currentTimeMillis() - startSetupTime);
            if (setupDurationMs<TorConfig.maxAllowedSetupDurationMs) {
                established = true;
                log.info("Circuit: " + toString() + " established within " + setupDurationMs + " ms - OK");
                queueFlowControlHandler = new QueueFlowControlHandler(this,circuitLevelFlowControl,circuitLevelFlowControlIncrement);
                queue.addHandler(queueFlowControlHandler);
                // fire event
                torEventService.fireEvent(new TorEvent(TorEvent.CIRCUIT_BUILD,this,"Circuit build " + toString()));
                successful = true;
            } else {
                log.info("Circuit: close-after-create " + toString() + ", because established within " + setupDurationMs + " ms was too long");
                close(true);
            }
        } finally {
            numberOfCircuitsInConstructor--;
            if (!successful) {
                close(true);
            }
        }
    }

    /**
     * CellRelayIntroduce2: From the Introduction Point to Bob's OP (section 1.9 of Tor Rendezvous Specification)
     * 
     * We only support version 2 here.
     * 
     * does exactly that: - check introduce2 for validity and connect to rendezvous-point
     */
    boolean handleIntroduce2(CellRelay cell) throws TorException, IOException {
        // parse introduce2-cell
        log.info("Circuit.handleIntroduce2: received Intro2-Cell of length="+cell.getLength());
        if (cell.getLength()<20) { 
          throw new TorException("Circuit.handleIntroduce2: cannot parse content, cell is too short");
        }
        byte[] identifier = new byte[20];
        System.arraycopy(cell.data,0,identifier,0,20);
        HiddenServiceProperties introProps = getHiddenServiceInstanceForIntroduction().getHiddenServiceProperties();
        if (!Encoding.arraysEqual(identifier, introProps.getPubKeyHash())) {
            throw new TorException("Circuit.handleIntroduce2: onion is for unknown key-pair");
        }
        byte[] onionData = new byte[cell.getLength()-20];
        System.arraycopy(cell.data,20,onionData,0,cell.getLength()-20);
        
        byte[] plainIntro2 = Encryption.asymDecrypt(introProps.getPrivateKey(), onionData);

        // TODO: deal with introduce2 version 1 - 3
        log.fine("   Intro2-Cell with plainIntro of lenght="+plainIntro2.length);

        // extract content from decoded Intro2 (v2 intro protocol)
        byte[] version = new byte[1];
        byte[] rendezvousPointAddress = new byte[4];
        // byte[] rendezvousPointPort = new byte[2]; (not needed because read directly from big byte array)
        byte[] rendezvousPointIdentityID = new byte[20];
        // byte[] rendezvousPointOnionKeyLen = new byte[2]; (not needed because read directly from big byte array)
        byte[] rendezvousPointOnionKey;
        final byte[] cookie = new byte[20];
        final byte[] dhX = new byte[128];
  
        int i = 0;
        System.arraycopy(plainIntro2, i, version, 0, version.length);
        i+=version.length;
        log.info("version="+version[0]);
        System.arraycopy(plainIntro2, i, rendezvousPointAddress, 0, rendezvousPointAddress.length);
        i+=rendezvousPointAddress.length;
        int rendezvousPointPort = Encoding.byteArrayToInt(plainIntro2, i, 2);
        i+=2;
        System.arraycopy(plainIntro2, i, rendezvousPointIdentityID, 0, rendezvousPointIdentityID.length);
        i+=rendezvousPointIdentityID.length;
        int rendezvousPointOnionKeyLength = Encoding.byteArrayToInt(plainIntro2, i, 2);
        i+=2;
        rendezvousPointOnionKey = new byte[rendezvousPointOnionKeyLength];
        System.arraycopy(plainIntro2, i, rendezvousPointOnionKey, 0, rendezvousPointOnionKey.length);
        i+=rendezvousPointOnionKey.length;
        System.arraycopy(plainIntro2, i, cookie, 0, cookie.length);
        i+=cookie.length;
        System.arraycopy(plainIntro2, i, dhX, 0, dhX.length);
        i+=dhX.length;
        
        // determine rendezvous point router,
        // try both byte order variants - TODO: find the correct way
        TcpipNetAddress rendezvousPointTcpipNetAddress1 = new TcpipNetAddress(rendezvousPointAddress, rendezvousPointPort);
        RouterImpl rendezvousServer1 = directory.getValidRouterByIpAddressAndOnionPort(rendezvousPointTcpipNetAddress1.getIpNetAddress(), rendezvousPointTcpipNetAddress1.getPort());
        log.info("rendezvousServer1="+rendezvousServer1);
        // change byte order - TODO: find the correct way
        byte[] rendezvousPointAddress2 = new byte[4];
        rendezvousPointAddress2[0] = rendezvousPointAddress[3];
        rendezvousPointAddress2[1] = rendezvousPointAddress[2];
        rendezvousPointAddress2[2] = rendezvousPointAddress[1];
        rendezvousPointAddress2[3] = rendezvousPointAddress[0];
        TcpipNetAddress rendezvousPointTcpipNetAddress2 = new TcpipNetAddress(rendezvousPointAddress2, rendezvousPointPort);
        RouterImpl rendezvousServer2 = directory.getValidRouterByIpAddressAndOnionPort(rendezvousPointTcpipNetAddress2.getIpNetAddress(), rendezvousPointTcpipNetAddress2.getPort());
        log.info("rendezvousServer2="+rendezvousServer2);
        // result
        final RouterImpl rendezvousServer = (rendezvousServer1!=null) ? rendezvousServer1 : rendezvousServer2;
        log.info("rendezvousServer="+rendezvousServer);

        // check version
        log.info("received Introduce2 cell with rendevouz point server="+rendezvousServer);
        if (version[0]!=2) {
            log.warning("Intro2-Cell not supported with version="+version[0]);
            return false;
        }
        
        // do the rest in an extra thread/in background
        new Thread() {
            public void run() {
                // build circuit to rendezvous
                TCPStreamProperties sp = new TCPStreamProperties();
                sp.setExitPolicyRequired(false);
                sp.setCustomExitpoint(rendezvousServer.getFingerprint());
        
                // make new circuit where the last node is rendezvous point
                for(int j=0; j<sp.getConnectRetries(); ++j) {
                    try {
                        final Circuit c2rendezvous = CircuitAdmin.provideSuitableNewCircuit(tlsConnectionAdmin, directory, sp, torEventService);
                        if (c2rendezvous==null) {
                            continue;
                        }
                        // send dhY
                        Node virtualNode = new Node(rendezvousServer, dhX);
                        c2rendezvous.sendCell(new CellRelayRendezvous1(c2rendezvous, cookie, virtualNode.getDhYBytes(), virtualNode.getKh()));
                        log.info("Circuit.handleIntroduce2: connected to rendezvous '" + rendezvousServer + "' over " + c2rendezvous.toString());
            
                        // extend circuit to 'virtual' next point AFTER doing the rendezvous
                        c2rendezvous.addNode(virtualNode);
                        
                        // connect - with empty address in begin cell set
                        c2rendezvous.setHiddenServiceInstanceForRendezvous(hiddenServiceInstanceForIntroduction);

                        break;

                    } catch (Exception e) {
                        log.log(Level.WARNING, "Exception in handleIntroduce2", e);
                    }
                }
            }
        }.start();
        /* https://gitweb.torproject.org/torspec.git/blob/HEAD:/rend-spec.txt - 1.10. Rendezvous*/
        return false;
    }

    
    /**
     * CellRelayBegin received for hidden service.
     * 
     * @param cell
     */
    void handleHiddenServiceStreamBegin(CellRelay cell, int streamId) throws TorException, IOException {
        // new stream requested on a circuit that was already established to the rendezvous point
        log.info("new stream requested on a circuit that was already established to the rendezvous point");
        
        // determine requested port number (is between ':' and [00])
        byte[] cellData = cell.getData();
        log.info("handleHiddenServiceStreamBegin with data="+ByteArrayUtil.showAsStringDetails(cellData));
        final int DEFAULT_PORT = -1;
        final int MAX_PORTSTR_LEN = 5;
        int port = DEFAULT_PORT;
        if (cellData[0]==':') {
            // yes: ':' is at the first position
            int startIndex = 1;
            int portNum = 0;
            for (int i=0; i<MAX_PORTSTR_LEN; i++) {
                char c = (char)cellData[startIndex+i];
                if (!Character.isDigit(c)) {
                    break;
                }
                portNum = 10*portNum+(c-'0');
            }
            port=portNum;
        }
        log.info("new stream on port="+port);
        
        // add new TCPStream to NetServerSocket
        HiddenServiceInstance hiddenServiceInstance = getHiddenServiceInstanceForRendezvous();
        HiddenServicePortInstance hiddenServicePortInstance = hiddenServiceInstance.getHiddenServicePortInstance(port);
        if (hiddenServicePortInstance!=null) {
            // accept stream
            hiddenServicePortInstance.createStream(this,  streamId);
            log.info("added new TCPStream to NetServerSocket/hiddenServicePortInstance="+hiddenServicePortInstance);
        } else {
            // reject stream because nobody is listen to this port
            log.info("rejected stream because nobody is listen on port="+port+" of hiddenServiceInstance="+hiddenServiceInstance);
            // TODO: send cell to signal the rejection instead of letting stream time out
        }
    }    
    
    /**
     * sends a cell on this circuit. Incoming data is received by the class
     * TLSDispatcher and then put in the queue.
     * 
     * @param c
     *            the cell
     * @exception IOException
     * @see TLSDispatcherThread
     */
    public void sendCell(Cell c) throws IOException {
        // update 'action'-timestamp, if not padding cell
        lastCell = new Date();
        if (!c.isTypePadding()) {
            lastAction = lastCell;
        }
        // send cell
        try {
            tls.sendCell(c);
        }
        catch(IOException e) {
            // if there's an error in sending it can only mean that the
            // circuit or the TLS-connection has severe problems. better close it
            if (!closed) {
                close(false);
            }
            throw e;
        }
    }

    /** creates and send a padding-cell down the circuit */
    public void sendKeepAlive() {
        try {
            sendCell(new CellPadding(this));
        } catch (IOException e) {
        }
    }

    /**
     * initiates circuit, sends CREATE-cell. throws an error, if something went
     * wrong
     */
    private void create(RouterImpl init) throws IOException, TorException {
        // save starting point
        routeNodes[0] = new Node(init);
        // send create cell, set circID
        sendCell(new CellCreate(this));
        // wait for answer
        Cell created = queue.receiveCell(Cell.CELL_CREATED);
        // finish DH-exchange
        routeNodes[0].finishDh(created.getPayload());
    }

    /**
     * Extends the existing circuit one more hop. sends an EXTEND-cell.
     */
    private void extend(int i, RouterImpl next) throws IOException, TorException {
        // save next node
        routeNodes[i] = new Node(next);
        // send extend cell
        sendCell(new CellRelayExtend(this, routeNodes[i]));
        // wait for extended-cell
        CellRelay relay = queue.receiveRelayCell(CellRelay.RELAY_EXTENDED);
        // finish DH-exchange
        routeNodes[i].finishDh(relay.data);
    }

    /**
     * adds node as the last one in the route
     * 
     * @param n
     *            new node that is appended to the existing route
     */
    public void addNode(Node n) {
        // create a new array for route that is one entry larger
        Node[] newRoute = new Node[routeEstablished + 1];
        System.arraycopy(routeNodes, 0, newRoute, 0, routeEstablished);
        // add new node
        newRoute[routeEstablished] = n;
        ++routeEstablished;
        // route to set new array
        routeNodes = newRoute;
    }

    /** used to report that this stream cause some trouble (either by itself,
     *  or the remote server, or what ever)
     */
    public void reportStreamFailure(Stream stream) {
      ++streamFails;
      // if it's just too much, 'soft'-close this circuit
      if ((streamFails>TorConfig.circuitClosesOnFailures)&&(streamFails > streamCounter*3/2)) {
          if (!closed) {
              log.info("Circuit.reportStreamFailure: closing due to failures "+toString());
          }
          close(false);
      }
      // include in ranking
      updateRanking();
    }

    /**
     * find a free stream ID, other than zero
     */
    private synchronized int getFreeStreamID() throws TorException {
        for (int nr = 1; nr < 0x10000; ++nr) {
            int id = (nr + streamCounter) & 0xffff;
            if (id != 0) {
                if (!streams.containsKey(id)) {
                    return id;
                }
            }
        }
        throw new TorException("Circuit.getFreeStreamID: " + toString()
                  + " has no free stream-IDs");
    }

    /**
     * find a free stream-id, set it in the stream s
     * 
     * @param s
     */
    public int assignStreamId(Stream s) throws TorException {
        // assign stream ID and memorize stream
        int streamId = getFreeStreamID();
        if (!assignStreamId(s, streamId)) {
            throw new TorException("streamId="+streamId+" could not be set");
        }
        return streamId;
    }

    /**
     * set the specified stream id to the stream
     * 
     * @param s
     * @param streamId
     * @return true=success, false=stream id is already in use
     */
    public boolean assignStreamId(Stream s, int streamId) throws TorException {
        if (closed) {
            throw new TorException("Circuit.assignStreamId: " + toString() + "is closed");
        }
        // assign stream ID and memorize stream

        s.setId(streamId);
        Stream oldStream = streams.put(streamId, s);
        if (oldStream==null) {
            // success
            return true;
        } else {
            // streamID was already used - rollback operation
            streams.put(streamId, oldStream);
            return false;
        }
    }

    /**
     * registers a stream in the history to allow bundeling streams to the same
     * connection in one circuit
     */
    void registerStream(TCPStreamProperties sp) throws TorException {
        ++establishedStreams;
        if (sp.getAddr() != null) {
            streamHistory.add(sp.getAddr());
        }
        if (sp.getHostname() != null) {
            streamHistory.add(sp.getHostname());
        }
    }

    /**
     * registers a stream in the history to allow bundeling streams to the same
     * connection in one circuit, wrapped for setting stream creation time
     */
    public void registerStream(TCPStreamProperties sp, long streamSetupDuration) throws TorException {

        sumStreamsSetupDelays += streamSetupDuration;
        streamCounter++;  
        updateRanking();
        registerStream(sp);
    }


    /**
     * updates the ranking of the circuit. takes into account: setup time of circuit and
     * streams. but also number of stream-failures on this circuit;
     *
     */
    private void updateRanking(){
        // do a weighted average of all setups. weighten the setup-time of the circuit more
        // then those of the single streams. thus streams will be rather unimportant at the
        // beginning, but play a more important role afterwards.
        ranking = (TorConfig.CIRCUIT_ESTABLISHMENT_TIME_IMPACT * setupDurationMs + sumStreamsSetupDelays)/
                        (streamCounter + TorConfig.CIRCUIT_ESTABLISHMENT_TIME_IMPACT);
        // take into account number of stream-failures on this circuit
        // DEPRECATED: just scale this up linearly
        //         ranking *= 1 + streamFails;
        // NEW: be cruel! there should be something severe for 3 or 4 errors!
        ranking *= Math.exp(streamFails);
    }


    /**
     * closes the circuit. either soft (remaining connections are kept, no new
     * one allowed) or hard (everything is closed immediately, e.g. if a destroy
     * cell is received)
     */
    public boolean close(boolean force) {
        if (!closed) {
            log.info("Circuit.close(): closing " + toString());
            // remove servers from list of currently used nodes
            for (int i = 0; i < routeEstablished; ++i) {
                Fingerprint f = routeNodes[i].getRouter().getFingerprint();
                Integer numberOfNodeOccurances = CircuitAdmin.getCurrentlyUsedNode(f);
                if (numberOfNodeOccurances!=null) {
                    // decrement the counter
                    CircuitAdmin.putCurrentlyUsedNodeNumber(f, Math.max(0, --numberOfNodeOccurances));
                }
            }
        }
        torEventService.fireEvent(new TorEvent(TorEvent.CIRCUIT_CLOSED,this,"Circuit: closing "+toString()));

        // mark circuit closed. do nothing more, is soft close and streams are
        // left
        closed = true;
        established = false;
        // close all streams, removed closed streams
        for (Stream stream : new ArrayList<Stream>(streams.values())) {
            try {
                // check if stream is still alive
                if (!stream.isClosed()) {
                    if (force) {
                        stream.close(force);
                    } else {
                        // check if we can time-out the stream?
                        if (System.currentTimeMillis() - stream.getLastCellSentDate().getTime() > 10 * TorConfig.queueTimeoutStreamBuildup * 1000) {
                            // ok, fsck it!
                            log.info("Circuit.close(): forcing timeout on stream");
                            stream.close(true);
                        } else {
                            // no way...warning
                            log.fine("Circuit.close(): can't close due to " + stream.toString());
                        }
                    }
                }
                if (stream.isClosed()) {
                    streams.remove(stream.getId());
                }
            } catch (Exception e) {
                log.log(Level.WARNING, "unexpected " + e, e);
            }
        }
        // 
        if ((!force) && (!streams.isEmpty())) {
            return false;
        }
        // gracefully kill circuit with DESTROY-cell or so
        if (!force) {
            if (routeEstablished > 0) {
                // send a destroy-cell to the first hop in the circuit only
                log.fine("Circuit.close(): destroying " + toString());
                routeEstablished = 1;
                try {
                    sendCell(new CellDestroy(this));
                } catch (IOException e) {
                    log.finer("Exception while destroying circuit: "+e);
                }
            }
        }

        // close circuit (also removes handlers)
        log.fine("Circuit.close(): close queue? " + toString());
        if (queue!=null) {
            log.fine("Circuit.close(): close queue! " + toString());
            queue.close();
        }
        
        // cleanup and maybe close tls
        destruct = true;
        log.fine("Circuit.close(): remove from tls? " + toString());
        if (tls!=null) {
            log.fine("Circuit.close(): remove from tls! " + toString());
            tls.removeCircuit(getId());
        }

        // closed
        log.fine("Circuit.close(): done " + toString());
        return true;
    }

    /** returns the route of the circuit. used to display route on a map or the like */
    public RouterImpl[] getRoute() {
        RouterImpl[] s = new RouterImpl[routeEstablished];
        for (int i = 0; i < routeEstablished; ++i) {
            s[i] = routeNodes[i].getRouter();
        }
        return s;
    }

    /** used for description */
    public String toString() {
        if (tls != null && tls.getRouter() != null) {
            Router r1 = tls.getRouter();
            StringBuffer sb = new StringBuffer(id + " [" + r1.getNickname() + "/"+ r1.getFingerprint() + " (" + r1.getCountryCode() + ")");
            for (int i = 1; i < routeEstablished; ++i) {
                Router r = routeNodes[i].getRouter();
                sb.append(" " + r.getNickname() + "/" + r.getHostname()+":"+r.getOrPort()+"/"+ r.getFingerprint() + " (" + r.getCountryCode() + ")");
            }
            sb.append("]");
            if (closed) {
                sb.append(" (closed)");
            } else {
                if (!established) {
                    sb.append(" (establishing)");
                }
            }
            return sb.toString();
        } else {
            return "<empty>";
        }
    }

    /**
     * 
     * @param streamId
     * @return true=removed; false=could not remove/did not exist 
     */
    public boolean removeStream(Integer streamId) {
        synchronized(streams) {
            boolean result = streams.remove(streamId)!=null;
            if (closeCircuitIfLastStreamIsClosed && streams.size()==0) {
                close(true);
            }
            return result;
        }
    }

    ///////////////////////////////////////////////////////
    // getters and setters
    ///////////////////////////////////////////////////////

    
    public void setHiddenServiceInstanceForIntroduction(HiddenServiceInstance hiddenServiceInstanceForIntroduction) {
        this.hiddenServiceInstanceForIntroduction = hiddenServiceInstanceForIntroduction;
    }
    HiddenServiceInstance getHiddenServiceInstanceForIntroduction() {
        return hiddenServiceInstanceForIntroduction;
    }
    public boolean isUsedByHiddenServiceToConnectToIntroductionPoint() {
        return hiddenServiceInstanceForIntroduction!=null;
    }
    

    private void setHiddenServiceInstanceForRendezvous(HiddenServiceInstance hiddenServiceInstanceForRendezvous) {
        this.hiddenServiceInstanceForRendezvous = hiddenServiceInstanceForRendezvous;
    }
    HiddenServiceInstance getHiddenServiceInstanceForRendezvous() {
        return hiddenServiceInstanceForRendezvous;
    }
    boolean isUsedByHiddenServiceToConnectToRendezvousPoint() {
        return hiddenServiceInstanceForRendezvous!=null;
    }


    public TorEventService getTorEventService() {
        return torEventService;
    }

    public Node[] getRouteNodes() {
        return routeNodes;
    }

    public void setRouteNodes(Node[] routeNodes) {
        this.routeNodes = routeNodes;
    }

    /**
     * 
     * @return number of nodes in the route, where the keys have been established
     */
    public int getRouteEstablished() {
        return routeEstablished;
    }

    public void setRouteEstablished(int routeEstablished) {
        this.routeEstablished = routeEstablished;
    }

    public Queue getQueue() {
        return queue;
    }

    public void setQueue(Queue queue) {
        this.queue = queue;
    }

    public Map<Integer, Stream> getStreams() {
        synchronized (streams) {
            return new HashMap<Integer, Stream>(streams);
        }
    }

    public HashSet<Object> getStreamHistory() {
        return streamHistory;
    }

    public int getEstablishedStreams() {
        return establishedStreams;
    }

    public void setEstablishedStreams(int establishedStreams) {
        this.establishedStreams = establishedStreams;
    }


    public int getId() {
        return id;
    }

    public boolean isEstablished() {
        return established;
    }

    public void setEstablished(boolean established) {
        this.established = established;
    }

    public boolean isClosed() {
        return closed;
    }

    public boolean isDestruct() {
        return destruct;
    }

    public Date getCreated() {
        return created;
    }

    public void setCreated(Date created) {
        this.created = created;
    }

    public Date getLastAction() {
        return lastAction;
    }

    public void setLastAction(Date lastAction) {
        this.lastAction = lastAction;
    }

    public Date getLastCell() {
        return lastCell;
    }

    public void setLastCell(Date lastCell) {
        this.lastCell = lastCell;
    }

    public int getSetupDurationMs() {
        return setupDurationMs;
    }

    public void setSetupDurationMs(int setupDurationMs) {
        this.setupDurationMs = setupDurationMs;
    }

    public int getRanking() {
        return ranking;
    }

    public void setRanking(int ranking) {
        this.ranking = ranking;
    }

    public int getSumStreamsSetupDelays() {
        return sumStreamsSetupDelays;
    }

    public void setSumStreamsSetupDelays(int sumStreamsSetupDelays) {
        this.sumStreamsSetupDelays = sumStreamsSetupDelays;
    }

    public int getStreamCounter() {
        return streamCounter;
    }

    public void setStreamCounter(int streamCounter) {
        this.streamCounter = streamCounter;
    }

    public int getStreamFails() {
        return streamFails;
    }

    public void setStreamFails(int streamFails) {
        this.streamFails = streamFails;
    }

    public QueueFlowControlHandler getQueueFlowControlHandler() {
        return queueFlowControlHandler;
    }

    public void setQueueFlowControlHandler(
            QueueFlowControlHandler queueFlowControlHandler) {
        this.queueFlowControlHandler = queueFlowControlHandler;
    }

    public Directory getDirectory() {
        return directory;
    }

    public void setDirectory(Directory directory) {
        this.directory = directory;
    }

    public TLSConnectionAdmin getTlsConnectionAdmin() {
        return tlsConnectionAdmin;
    }

    public void setTlsConnectionAdmin(TLSConnectionAdmin tlsConnectionAdmin) {
        this.tlsConnectionAdmin = tlsConnectionAdmin;
    }

    public RendezvousServiceDescriptor getServiceDescriptor() {
        return serviceDescriptor;
    }

    public void setServiceDescriptor(RendezvousServiceDescriptor serviceDescriptor) {
        this.serviceDescriptor = serviceDescriptor;
    }
    
    
    public boolean isCloseCircuitIfLastStreamIsClosed() {
        return closeCircuitIfLastStreamIsClosed;
    }

    public void setCloseCircuitIfLastStreamIsClosed(boolean closeCircuitIfLastStreamIsClosed) {
        this.closeCircuitIfLastStreamIsClosed = closeCircuitIfLastStreamIsClosed;
    }
}
