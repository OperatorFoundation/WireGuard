//
//  Configuration.swift
//  WireGuard
//
//  Created by Brandon Wiley on 11/20/17.
//  Copyright © 2017 Operator Foundation. All rights reserved.
//

import Foundation
import NetworkExtension

public struct Configuration {
    var privateKey: Data?
    var listenPort: Int16?
    var fwmark: Int?
    var replacePeers: Bool = true
    var publicKey: Data?
    var remove: Bool = true
    var presharedKey: Data?
    var endpoint: NWEndpoint?
    var persistentKeepaliveInternal: Int = 0
    var replaceAllowedIPs: Bool = true
    var allowedIP: String?

    /* Read-only properties */
    var rxBytes: Int {
        get {
            return _rxBytes
        }
    }
    private var _rxBytes: Int
    
    var txBytes: Int {
        get {
            return _txBytes
        }
    }
    private var _txBytes: Int
    
    var lastHandshakeTimeSec: Int {
        get {
            return _lastHandshakeTimeSec
        }
    }
    private var _lastHandshakeTimeSec: Int
    
    var lastHandshakeTimMsec: Int {
        get {
            return _lastHandshakeTimMsec
        }
    }
    private var _lastHandshakeTimMsec: Int
}
