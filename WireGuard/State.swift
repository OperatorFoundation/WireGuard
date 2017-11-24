//
//  State.swift
//  WireGuard
//
//  Created by Brandon Wiley on 11/20/17.
//  Copyright © 2017 Operator Foundation. All rights reserved.
//

import Foundation

struct State {
    var ii: Int32?
    var ir: Int32?
    var sprivi: Data?
    var sprivr: Data?
    var spubi: Data?
    var spubr: Data?
    var eprivi: Data?
    var eprivr: Data?
    var epubi: Data?
    var epubr: Data?
    var q: Data = Data(repeating: 0, count: 32)
    var hi: Data?
    var hr: Data?
    var ci: Data?
    var cr: Data?
    var tsendi: Data?
    var tsendr: Data?
    var trecvi: Data?
    var trecvr: Data?
    var nsendi: Data = Data(repeating: 0, count: 8)
    var nsendr: Data = Data(repeating: 0, count: 8)
    var nrecvi: Data?
    var nrecvr: Data?
    var cookie: Data?
    var cookieTimestamp: Date?

    init() {
        
    }
    
    mutating func incrNsendi() {
        
    }
    
    mutating func incrNsendr() {
        
    }
    
    mutating func makeTransportKeys() {
        assert(ci! == cr!, "Chaining keys for initiator and responder are not identical")
        let (temp1, temp2) = KDF2(key: ci!, data: e)
        tsendi=temp1
        trecvr=temp1
        trecvi=temp2
        tsendr=temp2
        
        nsendi=Data(repeating: 0, count: 8)
        nsendr=Data(repeating: 0, count: 8)
        nrecvi=Data(repeating: 0, count: 8)
        nrecvr=Data(repeating: 0, count: 8)
        
        eprivi=e
        epubi=e
        eprivr=e
        epubr=e
        ci=e
        cr=e
    }
}
