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

import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.layer.tor.api.TorNetLayerStatus;
import org.silvertunnel.netlib.layer.tor.circuit.Circuit;
import org.silvertunnel.netlib.layer.tor.circuit.CircuitsStatus;
import org.silvertunnel.netlib.layer.tor.circuit.Stream;
import org.silvertunnel.netlib.layer.tor.circuit.TLSConnection;
import org.silvertunnel.netlib.layer.tor.common.TCPStreamProperties;
import org.silvertunnel.netlib.layer.tor.common.TorConfig;
import org.silvertunnel.netlib.layer.tor.directory.DirectoryManagerThread;
import org.silvertunnel.netlib.layer.tor.stream.TCPStream;

/**
 * Management thread
 * 
 * @author Lexi Pimenidis
 * @author Michael Koellejan
 * @author hapke
 */
class TorBackgroundMgmtThread extends Thread {
    private static final Logger log = Logger.getLogger(TorBackgroundMgmtThread.class.getName());
    
    /** general factor seconds:milliseconds */
    static final int MILLISEC = 1000;
    /** time to sleep until first actions in seconds */
    static final int INITIAL_INTERVAL_S = 3;
    /**  time to wait between working loads in seconds */
    static final int INTERVAL_S = 3;
    /** interval of padding messages on circuits in seconds */
    static final int CIRCUITS_KEEP_ALIVE_INTERVAL_S = 30;
    /** interval of padding messages on streams in seconds */
    static final int STREAMS_KEEP_ALIVE_INTERVAL_S = 30;

    private static long idleThreadCounter = 0;
    
    /** reference to main class */
    private Tor tor;
    /**
     * at least this amount of circuits should always be available;
     * upper bound is (numberOfCircuits+tor.torConfig.circuitsMaximumNumber)
     */
    private int numberOfCircuits; 
    /** store the current time */
    private long currentTimeMillis;
    /** List of background threads (for graceful close) */
    private List<Thread> backgroundThreads; 
    /** As stop() is depreciated we follow the Sun recommendation */
    private boolean stopped = false;
    private DirectoryManagerThread directoryManagerThread;
    

    TorBackgroundMgmtThread(Tor tor, int numberOfCircuits) {
        this.backgroundThreads = new ArrayList<Thread>(numberOfCircuits);
        this.tor = tor;
        this.numberOfCircuits = numberOfCircuits;
        currentTimeMillis = System.currentTimeMillis();
        spawnIdleCircuits(numberOfCircuits);
        this.directoryManagerThread = new DirectoryManagerThread(tor.getDirectory());
        setName(getClass().getName());
        setDaemon(true);
        start();
    }

    /** create some empty circuits to have at hand - does so in the background */
    private void spawnIdleCircuits(int amount) {
        // Don't create circuits until not at least a certain fraction of the routers is known
        if (tor.getDirectory().isDirectoryReady()) {
            log.info("TorBackgroundMgmtThread.spawnIdleCircuits: Spawn "+amount+" new circuits");          
        } else {
            log.fine("Not yet spawning circuits (too few routers known until now)");
            return;
        }
          
        // Cleanup our background thread list
        ListIterator<Thread> brtIterator = backgroundThreads.listIterator();
        while (brtIterator.hasNext()) {
            Thread brt = brtIterator.next();
            if (!brt.isAlive()) {
                brtIterator.remove();
            }
        }

        // Spawn new background threads
        if (amount>0) {
            tor.updateStatus(TorNetLayerStatus.INITIAL_CICRUITES_ESTABLISHING);
        }
        for (int i = 0; i < amount; ++i) {
            Thread brt = new Thread() {
                public void run() {
                    try {
                        // idle threads should at least allow using port 80
                        TCPStreamProperties sp = new TCPStreamProperties();
                        sp.setPort(80);
                        new Circuit(tor.getTlsConnectionAdmin(), tor.getDirectory(), sp, tor.getTorEventService());
                    } catch (Exception e) {
                        log.fine("TorBackgroundMgmtThread.spawnIdleCircuits: "+e.getMessage());
                    }
                }
            };
            log.finer("TorBackgroundMgmtThread.spawnIdleCircuits: Circuit-Spawning thread started.");
            brt.setName("Idle Thread "+idleThreadCounter++);
            brt.start();
            backgroundThreads.add(brt);
        }
    }

    /**
     * sends keep-alive data on circuits
     */
    private void sendKeepAlivePackets() {
        for (TLSConnection tls : tor.getTlsConnectionAdmin().getConnections()) {
            for (Circuit c : tls.getCircuits()) {
                // check if this circuit needs a keep-alive-packet
                if ((c.isEstablished()) && (currentTimeMillis - c.getLastCell().getTime() > CIRCUITS_KEEP_ALIVE_INTERVAL_S * MILLISEC)) {
                    if (log.isLoggable(Level.FINER)) {
                        log.finer("TorBackgroundMgmtThread.sendKeepAlivePackets(): Circuit " + c.toString());
                    }
                    c.sendKeepAlive();
                }
                // check streams in circuit
                for (Stream streamX : c.getStreams().values()) {
                    TCPStream stream = (TCPStream)streamX;
                    if ((stream.isEstablished()) && (!stream.isClosed()) && (currentTimeMillis - stream.getLastCellSentDate().getTime() > STREAMS_KEEP_ALIVE_INTERVAL_S * MILLISEC)) {
                        if (log.isLoggable(Level.FINER)) {
                            log.finer("TorBackgroundMgmt.sendKeepAlivePackets(): Stream " + stream.toString());
                        }
                        stream.sendKeepAlive();
                    }
                }
            }
        }
    }

    /**
     * used to determine which (old) circuits can be torn down because there are
     * enough new circuits. or builds up new circuits, if there are not enough.
     */
    private void manageIdleCircuits() {
        CircuitsStatus circuitsStatus = tor.getCircuitsStatus();
        
        log.fine("TorBackgroundMgmt.manageIdleCircuits(): circuit counts: " +
                (circuitsStatus.getCircuitsAlive() - circuitsStatus.getCircuitsEstablished()) + " building, "
                + circuitsStatus.getCircuitsEstablished() + " established + "
                + circuitsStatus.getCircuitsClosed() + " closed = "
                + circuitsStatus.getCircuitsTotal());
        // check if enough 'alive' circuits are there
        if (circuitsStatus.getCircuitsAlive()+Circuit.numberOfCircuitsInConstructor < numberOfCircuits) {
            spawnIdleCircuits( (numberOfCircuits - circuitsStatus.getCircuitsAlive()) * 3 / 2 );
        } else if (circuitsStatus.getCircuitsEstablished() > numberOfCircuits + TorConfig.circuitsMaximumNumber) {
            // TODO: if for some reason there are too many established circuits. close the oldest ones
            log.fine("TorBackgroundMgmtThread.manageIdleCircuits(): kill " +
                    (numberOfCircuits + TorConfig.circuitsMaximumNumber - circuitsStatus.getCircuitsAlive()) + "new circuits (FIXME)");
        }
    }

    /**
     * used to close circuits that are marked for closing, but are still alive.
     * They are closed, if no more streams are contained.
     */
    private void tearDownClosedCircuits() {
        for (TLSConnection tls : tor.getTlsConnectionAdmin().getConnections()) {
            log.finer("check tls="+tls);
            if (tls.isClosed()) {
                log.fine("remove tls="+tls);
                tor.getTlsConnectionAdmin().removeConnection(tls);
            }
            for (Circuit c : tls.getCircuitMap().values()) {
                // check if stream is establishing but doesn't had any action
                // for a longer period of time
                for (Stream streamX : c.getStreams().values()) {
                    TCPStream s = (TCPStream)streamX;
                    long diff = (currentTimeMillis - s.getLastAction().getTime()) / MILLISEC;
                    if ((!s.isEstablished()) || s.isClosed()) {
                        if (diff > (2 * TorConfig.queueTimeoutStreamBuildup)) {
                            // log.info("close "+diff+" "+s.print());
                            log.fine("TorBackgroundMgmtThread.tearDownClosedCircuits(): closing stream (too long building) " + s.toString());
                            s.close(true);
                        } else {
                            // log.info("Checked "+diff+" "+s.print());
                        }
                    } else {
                        // log.info("OK "+diff+" "+s.print());
                    }
                }
                // check if circuit is establishing but doesn't had any action
                // for a longer period of time
                if ((!c.isEstablished()) && (!c.isClosed())) {
                    if ((currentTimeMillis - c.getLastAction().getTime()) / MILLISEC > (2 * TorConfig.queueTimeoutCircuit)) {
                        log.fine("TorBackgroundMgmtThread.tearDownClosedCircuits(): closing (too long building) " + c.toString());
                        c.close(false);
                    }
                }
                // check if this circuit should not accept more streams
                if (c.getEstablishedStreams() > TorConfig.streamsPerCircuit) {
                    log.fine("TorBackgroundMgmtThread.tearDownClosedCircuits(): closing (maximum streams) " + c.toString());
                    c.close(false);
                }
                // if closed, recall close() again and again to do garbage
                // collection and stuff
                if (c.isClosed()) {
                    c.close(false);
                }
                // check if this circuit can be removed from the set of circuits
                if (c.isDestruct()) {
                    log.fine("TorBackgroundMgmtThread.tearDownClosedCircuits(): destructing circuit " + c.toString());
                    tls.removeCircuit(c.getId());
                }
            }
        }
    }

    public void close() {
        // stop sub-thread
        directoryManagerThread.setStopped(true);
        directoryManagerThread.interrupt();
        // stop this thread
        this.stopped = true;
        this.interrupt();
    }

    public void cleanup() {
        ListIterator<Thread> brtIterator = backgroundThreads.listIterator();
        while (brtIterator.hasNext()) {
            Thread brt = brtIterator.next();
            if (brt.isAlive()) {
                brt.interrupt();
            }
            brtIterator.remove();
        }
    }

    public void run() {
        try {
            sleep(INITIAL_INTERVAL_S * MILLISEC);
        } catch (InterruptedException e) {
        }
        // run until killed
        outerWhile: while (!stopped) {
            try {
                currentTimeMillis = System.currentTimeMillis();
                // do work
                manageIdleCircuits();
                tearDownClosedCircuits();
                sendKeepAlivePackets();
                // update final state
                if (tor.getCircuitsStatus().getCircuitsEstablished() >= TorConfig.minimumIdleCircuits) {
                    tor.updateStatus(TorNetLayerStatus.READY);
                }
                // wait
                sleep(INTERVAL_S * MILLISEC);
            } catch (InterruptedException e) {
                log.log(Level.SEVERE, "stop thread1", e);
                break outerWhile;
            } catch (Exception e) {
                log.log(Level.SEVERE, "stop thread2", e);
                break outerWhile;
            }
        }
        cleanup();
    }
}
