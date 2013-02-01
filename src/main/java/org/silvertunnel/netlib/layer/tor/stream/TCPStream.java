/**
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
package org.silvertunnel.netlib.layer.tor.stream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.layer.tor.circuit.Cell;
import org.silvertunnel.netlib.layer.tor.circuit.CellRelay;
import org.silvertunnel.netlib.layer.tor.circuit.CellRelayBegin;
import org.silvertunnel.netlib.layer.tor.circuit.CellRelayConnected;
import org.silvertunnel.netlib.layer.tor.circuit.CellRelayDrop;
import org.silvertunnel.netlib.layer.tor.circuit.CellRelayEnd;
import org.silvertunnel.netlib.layer.tor.circuit.Circuit;
import org.silvertunnel.netlib.layer.tor.circuit.Queue;
import org.silvertunnel.netlib.layer.tor.circuit.QueueFlowControlHandler;
import org.silvertunnel.netlib.layer.tor.circuit.Stream;
import org.silvertunnel.netlib.layer.tor.clientimpl.Tor;
import org.silvertunnel.netlib.layer.tor.common.TCPStreamProperties;
import org.silvertunnel.netlib.layer.tor.common.TorConfig;
import org.silvertunnel.netlib.layer.tor.common.TorEvent;
import org.silvertunnel.netlib.layer.tor.directory.RouterImpl;
import org.silvertunnel.netlib.layer.tor.util.TorException;
import org.silvertunnel.netlib.layer.tor.util.TorNoAnswerException;


/**
 * handles the features of single TCP streams on top of circuits through the tor
 * network. provides functionality to send and receive data by this streams and
 * is publicly visible.
 * 
 * @author Lexi Pimenidis
 * @author Tobias Koelsch
 * @author Michael Koellejan
 */
public class TCPStream implements Stream, NetSocket {
    private static final Logger log = Logger.getLogger(TCPStream.class.getName());
    
    private static final int streamLevelFlowControlIncrement = 50;
    private int streamLevelFlowControl = 500;
    /** wait x seconds for answer */
    private int queueTimeout = TorConfig.queueTimeoutStreamBuildup;
    // TODO: do we need this?
    public static final int QUEUE_TIMEOUNT2 = 20;

    protected Circuit circuit;
    /** stream ID */
    protected int id;
    /** receives incoming data */
    protected Queue queue;
    private InetAddress resolvedAddress;
    //TODO: private TCPStreamProperties sp;
    private boolean established;
    private boolean closed;

    /** set by CellRelay. descriptive Strings are in CellRelay.REASON_TO_STRING */
    private int closedForReason;

    private QueueTor2JavaHandler qhT2J;
    private QueueFlowControlHandler qhFC;
    private TCPStreamOutputStream outputStream;

    private Date created;

    /** last time, a cell was send that was not a padding cell */
    private Date lastAction;

    /** last time, a cell was send */
    private Date lastCellSentDate; 

    /**
     * creates a stream on top of a existing circuit. users and programmers
     * should never call this function, but Tor.connect() instead.
     * 
     * @param c
     *            the circuit to build the stream through
     * @param sp
     *            the host etc. to connect to
     * @see Tor
     * @see Circuit
     * @see TCPStreamProperties
     */
    public TCPStream(Circuit c, TCPStreamProperties sp) throws IOException, TorException, TorNoAnswerException {
        // TODO: this.sp = sp;
        established = false;
        created = new Date();
        lastAction = created;
        lastCellSentDate = created;
        // stream establishment duration
        int setupDuration; 
        long startSetupTime; 

        // attach stream to circuit
        circuit = c;
        circuit.assignStreamId(this);
        queue = new Queue(queueTimeout);
        closed = false;
        closedForReason = 0;
        log.fine("TCPStream: building new stream " + toString());

        startSetupTime = System.currentTimeMillis();
        // send RELAY-BEGIN
        sendCell(new CellRelayBegin(this, sp));

        // wait for RELAY_CONNECTED
        CellRelay relay = null;
        try {
            log.fine("TCPStream: Waiting for Relay-Connected Cell...");
            relay = queue.receiveRelayCell(CellRelay.RELAY_CONNECTED);
            log.fine("TCPStream: Got Relay-Connected Cell");
        } catch (TorException e) {
            if (!closed) {
                // only msg, if closing was unintentionally
                log.log(Level.WARNING, "TCPStream: Closed: " + toString() + " due to TorException:" + e.getMessage());
            }
            closed = true;
            
            // MRK: when the circuit does not work at this point: close it
            // Lexi: please do it soft! there might be other streams
            //       working on this circuit...
            //c.close(false);
            // Lexi: even better: increase only a counter for this circuit
            //       otherwise circuits will close on an average after 3 or 4 
            //       streams. this is nothing we'd like to happen
            c.reportStreamFailure(this);
            
            throw e;
        } catch (IOException e) {
            closed = true;
            log.warning("TCPStream: Closed:" + toString() + " due to IOException:" + e.getMessage());
            throw e;
        }

        setupDuration = (int) (System.currentTimeMillis() - startSetupTime);

        // store resolved IP in TCPStreamProperties
        switch (relay.getLength()) {
        case 4+4:
            // IPv4 address
            byte[] ip = new byte[4];
            System.arraycopy(relay.getData(), 0, ip, 0, ip.length);
            try {
                resolvedAddress = InetAddress.getByAddress(ip);
                sp.setAddr(resolvedAddress);
                sp.setAddrResolved(true);
                log.finer("TCPStream: storing resolved IP " + resolvedAddress.toString());
            } catch (IOException e) {
                log.info("unexpected for resolved ip="+Arrays.toString(ip)+": "+e);
            }
            break;
        case 4+1+16+4:
            // IPv6 address
            // TODO: not yet implemented
            break;
        }

        // create reading threads to relay between user-side and tor-side
        //tor2java = new TCPStreamThreadTor2Java(this);
        //java2tor = new TCPStreamThreadJava2Tor(this);
        qhFC = new QueueFlowControlHandler(this,streamLevelFlowControl,streamLevelFlowControlIncrement);
        this.queue.addHandler(qhFC);
        qhT2J = new QueueTor2JavaHandler(this);
        this.queue.addHandler(qhT2J);
        outputStream = new TCPStreamOutputStream(this);

        log.info("TCPStream: build stream " + toString() + " within " + setupDuration + " ms");
        // attach stream to history
        circuit.registerStream(sp, setupDuration);
        established = true;
        // Tor.lastSuccessfulConnection = new Date(System.currentTimeMillis());
        circuit.getTorEventService().fireEvent(new TorEvent(TorEvent.STREAM_BUILD,this,"Stream build: "+toString()));
    }

    
    /**
     * creates a stream on top of a existing circuit. users and programmers
     * should never call this function, but Tor.connect() instead.
     * 
     * TODO: hidden-server-side.
     * 
     * Called after RELAY_BEGIN was received.
     * 
     * @param c
     *            the circuit to build the stream through
     * @param sp
     *            the host etc. to connect to
     * @see Tor
     * @see Circuit
     * @see TCPStreamProperties
     */
    public TCPStream(Circuit c, int streamId) throws IOException, TorException, TorNoAnswerException {
      //TODO: this.sp = sp;
        established = false;
        created = new Date();
        lastAction = created;
        lastCellSentDate = created;
        // stream establishment duration
        int setupDuration; 
        long startSetupTime; 

        // attach stream to circuit
        circuit = c;
        circuit.assignStreamId(this, streamId);
        queue = new Queue(QUEUE_TIMEOUNT2);
        closed = false;
        closedForReason = 0;
        log.fine("TCPStream(2): building new stream " + toString());

        startSetupTime = System.currentTimeMillis();
        /* TODO remove because not needed any more?
        while (true) {
            // wait for RELAY-BEGIN
            CellRelay relay = null;
            try {
                log.info("TCPStream(2): Waiting for Relay-Begin Cell...");
                relay = queue.receiveRelayCell(CellRelay.RELAY_BEGIN);
                log.info("TCPStream(2): Got Relay-Begin Cell");
            } catch (TorException e) {
                // only msg, if closing was unintentionally
                log.log(Level.WARNING, "TCPStream(2): Closed: " + toString() + " due to TorException:" + e.getMessage());
                //TODO: continue;
                throw e;
            } catch (IOException e) {
                log.warning("TCPStream(2): Closed:" + toString() + " due to IOException:" + e.getMessage());
              //TODO: continue;
                throw e;
            }
            break;
        }
        */
        
        // send RELAY_CONNECTED
        sendCell(new CellRelayConnected(this));
        
        setupDuration = (int) (System.currentTimeMillis() - startSetupTime);


        // create reading threads to relay between user-side and tor-side
        //tor2java = new TCPStreamThreadTor2Java(this);
        //java2tor = new TCPStreamThreadJava2Tor(this);
        qhFC = new QueueFlowControlHandler(this,streamLevelFlowControl,streamLevelFlowControlIncrement);
        this.queue.addHandler(qhFC);
        qhT2J = new QueueTor2JavaHandler(this);
        this.queue.addHandler(qhT2J);
        outputStream = new TCPStreamOutputStream(this);

        log.info("TCPStream: build stream " + toString() + " within " + setupDuration + " ms");
        // attach stream to history
        TCPStreamProperties sp = new TCPStreamProperties();
        circuit.registerStream(sp, setupDuration);
        established = true;
        // Tor.lastSuccessfulConnection = new Date(System.currentTimeMillis());
        circuit.getTorEventService().fireEvent(new TorEvent(TorEvent.STREAM_BUILD,this,"Stream build: "+toString()));
    }

    
    /** called from derived ResolveStream */
    protected TCPStream(Circuit c) {
        circuit = c;
    }

    public void sendCell(Cell c) throws IOException {
        // update 'action'-timestamp, if not padding cell
        lastCellSentDate = new Date();
        if (!c.isTypePadding()) {
            lastAction = lastCellSentDate;
        }
        // send cell
        try {
            circuit.sendCell(c);
        } catch(IOException e) {
            // if there's an error in sending a cell, close this stream
            this.circuit.reportStreamFailure(this);
            close(false);
            throw e;
        }
    }

    /** send a stream-layer dummy */
    public void sendKeepAlive() {
        try {
            sendCell(new CellRelayDrop(this));
        } catch (IOException e) {
        }
    }

    /** for application interaction */
    public void close() {
        // gracefully close stream
        close(false);
        // remove from circuit
        log.finer("TCPStream.close(): removing stream " + toString());
        circuit.removeStream(id);
    }

    /**
     * for internal usage
     * 
     * @param force
     *            if set to true, just destroy the object, without sending
     *            END-CELLs and stuff
     */
    public void close(boolean force) {
        log.fine("TCPStream.close(): closing stream " + toString());
        circuit.getTorEventService().fireEvent(new TorEvent(TorEvent.STREAM_CLOSED,this,"Stream closed: "+toString()));
        
        // if stream is not closed, send a RELAY-END-CELL
        if (!(closed || force)) {
            try {
                sendCell(new CellRelayEnd(this, (byte) 6)); // send cell with 'DONE'
            } catch (IOException e) {
            }
        }
        // terminate threads gracefully
        closed = true;
        /*if (!force) {
            try {
                this.wait(3);
            } catch (Exception e) {
            }
        }*/
        // terminate threads if they are still alive
        if (outputStream != null) {
            try {
                outputStream.close();
            } catch (Exception e) {
            }
        }
        // close queue (also removes handlers)
        queue.close();
        // remove from circuit
        circuit.removeStream(id);
    }

    /**
     * use this to receive data by the anonymous data stream
     * 
     * @return a standard Java-Inputstream
     */
    public InputStream getInputStream() {
        return qhT2J.getInputStream();
    }

    /**
     * use this to transmit data through the Tor-network
     * 
     * @return a standard Java-Outputstream
     */
    public OutputStream getOutputStream() {
        return outputStream;
    }

    /** used for proxy and UI */
    public String getRoute() {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < circuit.getRouteEstablished(); ++i) {
            RouterImpl r = circuit.getRouteNodes()[i].getRouter();
            sb.append(", ");
            sb.append(r.getNickname() + " (" + r.getCountryCode() + ")");
        }
        return sb.toString();
    }

    /** for debugging */
    public String toString() {
        /* TODO:
        if (sp == null) {
            return id + " on circuit " + circuit.toString() + " to nowhere";
        } else {
            if (closed) {
                return id + " on circuit " + circuit.toString() + " to " + sp.getHostname() + ":" + sp.getPort() + " (closed)";
            } else {
                return id + " on circuit " + circuit.toString() + " to " + sp.getHostname() + ":" + sp.getPort();
            }
        }
        */
        if (closed) {
            return id + " on circuit " + circuit.toString() + " to ??? (closed)";
        } else {
            return id + " on circuit " + circuit.toString() + " to ???";
        }
   }
    
    ///////////////////////////////////////////////////////
    // getters and setters
    ///////////////////////////////////////////////////////
    
    public void setId(int id) {
        if (this.id==0) {
            // set initial ID
            this.id = id;
        } else {
            // replace id
            this.id = id;
            log.warning("replaced TCPStream.ID "+this.id+" by "+id);
        }
    }

    public int getId() {
        return id;
    }

    public Date getLastCellSentDate() {
        return lastCellSentDate;
    }
    
    public boolean isClosed() {
        return closed;
    }
    
    void setClosed(boolean closed) {
        this.closed = closed;
    }
    
    public Circuit getCircuit() {
        return circuit;
    }
    
    public Queue getQueue() {
        return queue;
    }

    public int getQueueTimeout() {
        return queueTimeout;
    }

    public InetAddress getResolvedAddress() {
        return resolvedAddress;
    }

    /* TODO
    public TCPStreamProperties getSp() {
        return sp;
    }
    */

    public boolean isEstablished() {
        return established;
    }

    public int getClosedForReason() {
        return closedForReason;
    }

    public void setClosedForReason(int closedForReason) {
        this.closedForReason = closedForReason;
    }

    public Date getCreated() {
        return created;
    }

    public Date getLastAction() {
        return lastAction;
    }

    public int getStreamLevelFlowControl() {
        return streamLevelFlowControl;
    }

    public int getStreamLevelFlowControlIncrement() {
        return streamLevelFlowControlIncrement;
    }
}

