//
//  WireGuardTests.swift
//  WireGuardTests
//
//  Created by Brandon Wiley on 11/20/17.
//  Copyright © 2017 Operator Foundation. All rights reserved.
//

import XCTest

@testable import WireGuard

class WireGuardTests: XCTestCase {
    var spubr: Data?
    var sprivr: Data?
    var spubi: Data?
    var sprivi: Data?

    override func setUp() {
        super.setUp()
        
        var pub: Data
        var priv: Data
        
        (pub, priv) = DHgenerate()
        spubr=pub
        sprivr=priv
        
        (pub, priv) = DHgenerate()
        spubi=pub
        sprivi=priv
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testInitiation() {
        let initiation=HandshakeInitiation(spubr: spubr!, sprivi: sprivi!, maybeStaticKey: nil)
        let initData=initiation.encode()
    }
}
