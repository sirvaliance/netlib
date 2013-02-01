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

import java.io.IOException;

import org.silvertunnel.netlib.layer.tor.util.Encoding;
import org.silvertunnel.netlib.layer.tor.util.TorException;


/**
 * this cell helps extending existing circuits
 * 
 * @author Lexi Pimenidis
 */
class CellRelayExtend extends CellRelay {
    /**
     * build an EXTEND-cell<br>
     * <ul>
     * <li>address (4 bytes)
     * <li>port (2 bytes)
     * <li>onion skin (186 bytes)
     * <li>hash (20 bytes)
     * </ul>
     * 
     * @param c
     *            the circuit that needs to be extended
     * @param next
     *            the node to which the circuit shall be extended
     * @throws IOException
     */
    CellRelayExtend(Circuit c, Node next) throws IOException, TorException {
        // initialize a new RELAY-cell
        super(c, CellRelay.RELAY_EXTEND);

        // Address [4 bytes] next.server.address
        byte[] address = next.getRouter().getAddress().getAddress();
        // Port [2 bytes] next.server.port
        byte[] orPort = Encoding.intToNByteArray(next.getRouter().getOrPort(), 2);
        // Onion skin [186 bytes]
        byte[] onionRaw = new byte[144];
        System.arraycopy(next.getSymmetricKeyForCreate(), 0, onionRaw, 0, 16);
        System.arraycopy(next.getDhXBytes(), 0, onionRaw, 16, 128);
        byte[] onionSkin = next.asymEncrypt(onionRaw);
        // Public key hash [20 bytes]
        // (SHA1-hash of the PKCS#1 ASN1-encoding of the next OR's signing key)
        byte[] keyHash = next.getRouter().getFingerprint().getBytes();

        // save everything in payload
        setLength(4 + 2 + 186 + 20);
        System.arraycopy(address, 0, data, 0, 4);
        System.arraycopy(orPort, 0, data, 4, 2);
        System.arraycopy(onionSkin, 0, data, 6, 186);
        System.arraycopy(keyHash, 0, data, 192, 20);
    }
}
