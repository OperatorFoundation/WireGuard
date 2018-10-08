//
//  State.swift
//  WireGuard
//
//  Created by Brandon Wiley on 11/20/17.
//  Copyright © 2017 Operator Foundation. All rights reserved.
//

import Foundation
import Sodium

public struct State {
    var ii: Int32!
    var ir: Int32!
    var static_private: Data!
    var sprivr: Data!
    var static_public: Data!
    var spubr: Data!
    var ephemeral_private: Data!
    var eprivr: Data!
    var ephemeral_public: Data!
    var epubr: Data!
    var q: Data = Data(repeating: 0, count: 32)
    var hash: Data!
    var hr: Data!
    var chaining_key: Data!
    var cr: Data!
    var tsendi: Data!
    var tsendr: Data!
    var trecvi: Data!
    var trecvr: Data!
    var sender_index: Data = Data(repeating: 0, count: 8)
    var nsendr: Data = Data(repeating: 0, count: 8)
    var nrecvi: Data!
    var nrecvr: Data!
    var last_received_cookie: Data!
    var cookieTimestamp: Date!

    public init() {
        
    }
    
    mutating func incrNsendi() {
        
    }
    
    mutating func incrNsendr() {
        
    }

    /*
     * https://www.wireguard.com/papers/wireguard.pdf
     * 5.4.5 Transport Key Data Derivation
     */
    mutating func makeTransportKeys() {
        assert(chaining_key! == cr!, "Chaining keys for initiator and responder are not identical")
        let (temp1, temp2) = KDF2(key: chaining_key!, data: e)
        tsendi=temp1
        trecvr=temp1
        trecvi=temp2
        tsendr=temp2
        
        sender_index=Data(repeating: 0, count: 8)
        nsendr=Data(repeating: 0, count: 8)
        nrecvi=Data(repeating: 0, count: 8)
        nrecvr=Data(repeating: 0, count: 8)
        
        zero(&ephemeral_private!)
        zero(&ephemeral_public!)
        zero(&eprivr!)
        zero(&epubr!)
        zero(&chaining_key!)
        zero(&cr!)
    }
}

// Note: This is not guaranteed to be secure. This is probably the best we can do in Swift, which does not provide secure memory management.
func zero(_ data: inout Data)
{
    for index in 0..<data.count
    {
        data[index]=0
    }
}
