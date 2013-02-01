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

import java.io.DataInputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.layer.tor.util.TorException;


/**
 * reads data arriving at the TLS connection and dispatches it to the
 * appropriate circuit or stream that it belongs to.
 * 
 * @author Lexi Pimenidis
 * @author hapke
 */
class TLSDispatcherThread extends Thread {
    private static final Logger log = Logger.getLogger(TLSDispatcherThread.class.getName());
    
    private DataInputStream sin;
    private TLSConnection tls;
    private boolean stopped;

    TLSDispatcherThread(TLSConnection tls, DataInputStream sin) {
        this.tls = tls;
        this.sin = sin;
        this.setName("TLSDispatcher for "+tls.getRouter().getNickname());
        this.start();
    }

    public void close() {
        this.stopped = true;
        this.interrupt();
    }

    public void run() {
        boolean dispatched = false;
        while(!stopped) {
            // read next data-packet
            Cell cell = null;
            try {
                cell = new Cell(sin);
            } catch (IOException e) {
                log.info("TLSDispatcher.run: connection error: "+e.getMessage());
                stopped = true;
                break;
            }
            // padding cell?
            if (cell.isTypePadding()) {
                if (log.isLoggable(Level.FINE)) {
                    log.fine("TLSDispatcher.run: padding cell from from " + tls.getRouter().getNickname());
                }
            } else {
                dispatched = false;
                int cellCircId = cell.getCircuitId();
                // dispatch according to circID
                Circuit circ = tls.getCircuit(cellCircId);
                if (circ != null) {
                    try { // admitted: this was not the original intent for queue handlers... but maybe I'll find a better solution sometimes in the future
                        if (circ.queueFlowControlHandler!=null) {
                            circ.queueFlowControlHandler.handleCell(cell);
                        }
                    } catch(TorException e) {}
                    // check for destination in circuit
                    if (cell.isTypeRelay()) {
                        CellRelay relay = null;
                        try {
                            // found a relay-cell! Try to strip off
                            // symmetric encryption and check the content
                            relay = new CellRelay(circ, cell);
                            if (log.isLoggable(Level.FINE)) {
                                log.fine("relay.getRelayCommand()="+relay.getRelayCommand());                            
                            }

                            // dispatch to stream, if a stream-ID is given
                            int streamId = relay.getStreamId();
                            if (streamId != 0) {
                                Stream stream = circ.getStreams().get(streamId);
                                if (log.isLoggable(Level.FINE)) {
                                    log.fine("dispatch to stream with streamId="+streamId+", stream="+stream);
                                }
                                if (stream!=null) {
                                    dispatched = true;
                                    if (log.isLoggable(Level.FINE)) {
                                        log.fine("TLSDispatcher.run: data from " + tls.getRouter().getNickname() + " dispatched to circuit " + circ.getId() + "/stream " + streamId);
                                    }
                                    stream.getQueue().add(relay);
                                } else if (circ.isUsedByHiddenServiceToConnectToRendezvousPoint() && relay.isTypeBegin()) {
                                    // new stream requested on a circuit that was already established to the rendezvous point
                                    circ.handleHiddenServiceStreamBegin(relay, streamId);
                                } else {
                                    // do nothing
                                    if (log.isLoggable(Level.FINE)) {
                                        log.fine("else: circ.isUsedByHiddenServiceToConnectToRendezvousPoint()="+circ.isUsedByHiddenServiceToConnectToRendezvousPoint()+", relay.getRelayCommand()="+relay.getRelayCommand());
                                    }
                                }
                            } else {
                                // relay cell for stream id 0: dispatch to
                                // circuit
                                if (relay.isTypeIntroduce2()) {
                                    if (circ.isUsedByHiddenServiceToConnectToIntroductionPoint()) {
                                        if (log.isLoggable(Level.FINE)) {
                                            log.fine("TLSDispatcher.run: introduce2 from " + tls.getRouter().getNickname() + " dispatched to circuit " + circ.getId() + " (stream ID=0)");
                                        }
                                        try {
                                            dispatched = circ.handleIntroduce2(relay);
                                        } catch(IOException e) {
                                            log.info("TLSDispatcher.run: error handling intro2-cell: "+e.getMessage());
                                        }
                                    } else {
                                        // do nothing
                                        if (log.isLoggable(Level.FINE)) {
                                            log.fine("else isTypeIntroduce2: from " + tls.getRouter().getNickname() + " dispatched to circuit " + circ.getId() + " (stream ID=0)");
                                        }
                                    }
                                } else {
                                    if (log.isLoggable(Level.FINE)) {
                                        log.fine("TLSDispatcher.run: data from " + tls.getRouter().getNickname() + " dispatched to circuit " + circ.getId() + " (stream ID=0)");
                                    }
                                    dispatched = true;
                                    circ.getQueue().add(relay);
                                }
                            }
                        } catch (TorException e) {
                            log.warning("TLSDispatcher.run: TorException " + e.getMessage() + " during dispatching cell");
                        } catch (Exception e) {
                            log.log(Level.WARNING, "TLSDispatcher.run: Exception " + e.getMessage() + " during dispatching cell", e);
                        }
                    } else {
                        // no relay cell: cell is there to control circuit
                        if (cell.isTypeDestroy()) {
                            if (log.isLoggable(Level.FINE)) {
                                log.fine("TLSDispatcher.run: received DESTROY-cell from " + tls.getRouter().getNickname() + " for circuit " + circ.getId());
                            }
                            dispatched = true;
                            circ.close(true);
                        } else {
                            if (log.isLoggable(Level.FINE)) {
                                log.fine("TLSDispatcher.run: data from " + tls.getRouter().getNickname() + " dispatched to circuit " + circ.getId());
                            }
                            dispatched = true;
                            circ.getQueue().add(cell);
                        }
                    }
                } else {
                    log.info("TLSDispatcher.run: received cell for circuit " + cellCircId + " from " + tls.getRouter().getNickname() + ". But no such circuit exists.");
                }
            }
            if (!dispatched) {
                // used to be WARNING, but is given too often to be of $REAL value, like a warning should
                if (log.isLoggable(Level.FINE)) {
                    log.fine("TLSDispatcher.run: data from " + tls.getRouter().getNickname() + " could not get dispatched");
                }
                if (log.isLoggable(Level.FINER)) {
                    log.finer("TLSDispatcher.run: " + cell.toString());
                }
            }
        }
    }
}
