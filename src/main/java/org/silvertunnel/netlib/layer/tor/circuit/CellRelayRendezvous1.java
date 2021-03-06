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
package org.silvertunnel.netlib.layer.tor.circuit;

/**
 * this cell is used to establish introduction point
 * 
 * @author Lexi Pimenidis
 */
class CellRelayRendezvous1 extends CellRelay {
    CellRelayRendezvous1(Circuit c, byte[] cookie, byte[] dhY, byte[] kh) {
        super(c, RELAY_RENDEZVOUS1);
        // copy to payload
        System.arraycopy(cookie, 0, data, 0, cookie.length);
        System.arraycopy(dhY, 0,   data, cookie.length, dhY.length);
        System.arraycopy(kh, 0,     data, cookie.length + dhY.length, kh.length);
        setLength(cookie.length + dhY.length + kh.length);
    }
}
