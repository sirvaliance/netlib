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

import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.layer.tor.directory.RouterImpl;
import org.silvertunnel.netlib.layer.tor.directory.SDIntroductionPoint;
import org.silvertunnel.netlib.layer.tor.util.Encoding;
import org.silvertunnel.netlib.layer.tor.util.Encryption;
import org.silvertunnel.netlib.layer.tor.util.TorException;
import org.silvertunnel.netlib.util.ByteArrayUtil;

/**
 * this cell is used to establish connection to the introduction point
 * 
 * @author Andriy Panchenko
 * @author hapke
 */
public class CellRelayIntroduce1 extends CellRelay {
    private static final Logger log = Logger.getLogger(CellRelayIntroduce1.class.getName());
    
    /**
     * CellRelayIntroduce1: from Alice's OP to Introduction Point (section 1.8 of Tor Rendezvous Specification)
     * 
     * We only support version 2 here.
     * 
     * @param c
     * @param rendezvousCookie
     * @param sd
     * @param rendezvousName
     * @param introPointServicePublicKeyNode
     * @throws TorException
     */
    public CellRelayIntroduce1(Circuit c, byte[] rendezvousCookie, SDIntroductionPoint introPoint,
            Node introPointServicePublicKeyNode, RouterImpl rendezvousPointRouter) throws TorException {
        super(c, RELAY_INTRODUCE1);

        //
        // clear text part
        //
        
        // PK_ID  Identifier for Bob's PK      [20 octets]
        byte[] clearText=Encryption.getDigest(Encryption.getPKCS1EncodingFromRSAPublicKey(introPoint.getServicePublicKey()));
        System.arraycopy(clearText, 0, data, 0, clearText.length);

        //
        // encrypted text part
        //
        byte[] rendezvousPointRouterOnionKey = Encryption.getPKCS1EncodingFromRSAPublicKey(rendezvousPointRouter.getOnionKey());
        byte[] unencryptedData = ByteArrayUtil.concatByteArrays(
                //
                // "just like the hybrid encryption in CREATE cells",
                // not explicitly mentioned in section 1.8 of Tor Rendezvous Specification
                //
                
                // OAEP padding [42 octets] (RSA-encrypted): gets added automatically
                // symmetric key [16 octets]
                introPointServicePublicKeyNode.getSymmetricKeyForCreate(),


                //
                // the rest as mentioned in section 1.8 of Tor Rendezvous Specification
                //
                
                // VER    Version byte: set to 2.        [1 octet]
                new byte[] {0x02},
                // IP     Rendezvous point's address    [4 octets]
                rendezvousPointRouter.getOrAddress().getIpaddress(),
                // PORT   Rendezvous point's OR port    [2 octets]
                Encoding.intTo2ByteArray(rendezvousPointRouter.getOrAddress().getPort()),
                // ID     Rendezvous point identity ID [20 octets]
                rendezvousPointRouter.getFingerprint().getBytes(),
                // KLEN   Length of onion key           [2 octets]
                Encoding.intTo2ByteArray(rendezvousPointRouterOnionKey.length),
                // KEY    Rendezvous point onion key [KLEN octets]
                rendezvousPointRouterOnionKey,
                // RC     Rendezvous cookie            [20 octets]
                rendezvousCookie,
                //g^x    Diffie-Hellman data, part 1 [128 octets]
                introPointServicePublicKeyNode.getDhXBytes()
        );
        byte[] encryptedData = introPointServicePublicKeyNode.asymEncrypt(unencryptedData);
        if (log.isLoggable(Level.FINE)) {
            log.fine("CellRelayIntroduce1: unencryptedData="+Encoding.toHexString(unencryptedData));
            log.fine("CellRelayIntroduce1: encryptedData="+Encoding.toHexString(encryptedData));
        }
        
        // set encrypted part
        System.arraycopy(encryptedData, 0, data, clearText.length, encryptedData.length);
        setLength(clearText.length + encryptedData.length);

        if (log.isLoggable(Level.FINE)) {
            log.fine("CellRelayIntroduce1: cell="+toString());
        }
    }
}
