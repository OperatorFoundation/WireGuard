//
//  Protocol.swift
//  WireGuard
//
//  Created by Brandon Wiley on 11/20/17.
//  Copyright © 2017 Operator Foundation. All rights reserved.
//

import Foundation
import Sodium
import Datable

let e = Data()

public struct HandshakeInitiation {
    let type: Data = Data(bytes: [0b10000000])
    let reserved: Data = Data(repeating: 0x00, count: 3)
    let sender: Data
    let ephemeralKey: Data
    let staticKey: Data
    let timestamp: Data
    let mac1: Data
    let mac2: Data
    var state: State=State()

    public init(spubr: Data, sprivi: Data, maybeStaticKey: Data?) {
        state.spubr=spubr
        state.sprivi=sprivi
        if let staticKey=maybeStaticKey {
            self.staticKey=staticKey
            state.q=staticKey
        } else {
            self.staticKey=state.q
        }

        sender=randomBytes(number: 4)!
        
        // 5.4.2
        state.ci=hash(data: construction)
        state.hi=hash(state.ci!, identifier)
        state.hi=hash(state.hi!, state.spubr!)
        let (eprivi, epubi) = DHgenerate()
        state.eprivi = eprivi
        state.epubi = epubi
        state.ci = KDF1(state.ci!, state.epubi!)
        ephemeralKey=state.epubi!
        
        NSLog("ci: \(String(describing: state.ci ?? nil)) sprivi: \(String(describing: state.sprivi ?? nil)) spubr: \(String(describing: state.spubr))")
        
        state.hi=hash(state.hi!, self.staticKey)
        let (tempci, k) = KDF2(key: state.ci!, data: DH(privateKey: state.sprivi!, publicKey: state.spubi!, peerPublicKey: state.spubr!))
        state.ci = tempci
        timestamp=AEAD(key: k, counter: Data(repeating: 0, count: 8), plainText: TAI64N(), authText: state.hi!)
        state.hi = hash(state.hi!, timestamp)
        
        let payload1 = concat([type, reserved, sender, ephemeralKey, staticKey, timestamp])
        
        mac1=MAC(key: hash(labelMac1, spubr), data: payload1)
        
        if let cookie = state.cookie, let timestamp = state.cookieTimestamp, timestamp.timeIntervalSinceNow < 120 {
            let payload2 = concat([payload1, mac1])
            mac2 = MAC(key: cookie, data: payload2)
        } else {
            mac2 = Data(repeating: 0, count: 16) // FIXME - different mac2 if cookies are present
        }
    }
    
    init(sender: Data, ephemeralKey: Data, staticKey: Data, timestamp: Data, mac1: Data, mac2: Data, sprivr: Data, spubr: Data) {
        self.sender=sender
        self.ephemeralKey=ephemeralKey
        self.staticKey=staticKey
        self.timestamp=timestamp
        self.mac1=mac1
        self.mac2=mac2
        
        state.spubr=spubr
        state.sprivr=sprivr
        state.q=self.staticKey
        
        // 5.4.2
        state.ci=hash(data: construction)
        state.hi=hash(state.ci!, identifier)
        state.hi=hash(state.hi!, state.spubr!)
        state.epubi = ephemeralKey
        state.ci = KDF1(state.ci!, state.epubi!)
        
        state.hi=hash(state.hi!, staticKey)
        let (tempci, k) = KDF2(key: state.ci!, data: DH(privateKey: state.sprivr!, publicKey: state.spubr!, peerPublicKey: state.spubi!))
        state.ci = tempci
        assert(timestamp == AEAD(key: k, counter: Data(repeating: 0, count: 8), plainText: TAI64N(), authText: state.hi!))
        state.hi = hash(state.hi!, timestamp)
        
        let payload1 = concat([type, reserved, sender, ephemeralKey, staticKey, timestamp])
        
        let newmac1=MAC(key: hash(labelMac1, spubr), data: payload1)
        
        assert(newmac1 == self.mac1)
        
        let newmac2 = Data(repeating: 0, count: 16) // FIXME - different mac2 if cookies are present
        
        assert(newmac2 == self.mac2)
    }
    
    public init(data: Data, sprivr: Data, spubr: Data) {
        let newtype = data[0 ..< 1]
        
        assert(newtype == Data(bytes: [0b10000000]))
        
        let newreserved = data[1 ..< 4]
        
        assert(newreserved == Data(repeating: 0x00, count: 3))
        
        let newsender = data[4 ..< 8]
        let newephemeralKey=data[8 ..< 40]
        let newstaticKey=data[40 ..< 88]
        let newtimestamp=data[88 ..< 116]
        let newmac1=data[116 ..< 132]
        let newmac2=data[132 ..< 148]
        
        self.init(sender: newsender, ephemeralKey: newephemeralKey, staticKey: newstaticKey, timestamp: newtimestamp, mac1: newmac1, mac2: newmac2, sprivr: sprivr, spubr: spubr)
    }
    
    public func encode() -> Data {
        return concat([type, reserved, sender, ephemeralKey, staticKey, timestamp, mac1, mac2])
    }
}

func concat(_ items: [Data]) -> Data {
    var temp = Data()
    for item in items {
        temp.append(item)
    }
    
    return temp
}

extension HandshakeInitiation: Equatable {
    public static func == (lhs: HandshakeInitiation, rhs: HandshakeInitiation) -> Bool {
        return
            lhs.sender == rhs.sender &&
            lhs.ephemeralKey == rhs.ephemeralKey &&
            lhs.staticKey == rhs.staticKey &&
            lhs.timestamp == rhs.timestamp &&
            lhs.mac1 == rhs.mac1 &&
            lhs.mac2 == rhs.mac2
    }
}

public struct HandshakeResponse {
    let type: Data = Data(bytes: [0b01000000])
    let reserved: Data = Data(repeating: 0x00, count: 3)
    let sender: Data
    let receiver: Data
    let ephemeralKey: Data
    let empty: Data
    let mac1: Data
    let mac2: Data
    var state: State=State()
    
    init(sender: Data, receiver: Data, ephemeralKey: Data, empty: Data, mac1: Data, mac2: Data, oldState: State) {
        self.sender=sender
        self.receiver=receiver
        self.ephemeralKey=ephemeralKey
        self.empty=empty
        self.mac1=mac1
        self.mac2=mac2
        self.state=oldState

        self.state.epubr=ephemeralKey
        self.state.cr=KDF1(self.state.cr!, self.state.epubr!)
        self.state.hr=hash(self.state.hr!, ephemeralKey)
        self.state.cr = KDF1(self.state.cr!, DH(privateKey: self.state.eprivr!, publicKey: self.state.epubr!, peerPublicKey: self.state.epubi!))
        self.state.cr = KDF1(self.state.cr!, DH(privateKey: self.state.eprivr!, publicKey: self.state.spubr!, peerPublicKey: self.state.spubi!))
        var t: Data
        var k: Data
        var tempcr: Data
        (tempcr, t, k) = KDF3(key: self.state.cr!, data: self.state.q)
        self.state.cr=tempcr
        self.state.hr = hash(self.state.hr!, t)
        assert(self.empty == AEAD(key: k, counter: Data(repeating: 0, count: 8), plainText: e, authText: self.state.hr!))
        self.state.hr=hash(self.state.hr!, empty)
        
        let payload = concat([type, reserved, sender, receiver, ephemeralKey, empty])
        
        let newmac1=MAC(key: hash(labelMac1, self.state.spubi!), data: payload)
        
        assert(newmac1 == mac1)
        
        let newmac2 = Data(repeating: 0, count: 16) // FIXME - different mac2 if cookies are present
        
        assert(newmac2 == mac2)
        
        state.makeTransportKeys()
    }

    public init(data: Data, initiation: HandshakeInitiation) {
        let newtype = data[0 ..< 1]
        
        assert(newtype == Data(bytes: [0b01000000]))
        
        let newreserved = data[1 ..< 4]
        
        assert(newreserved == Data(repeating: 0x00, count: 3))
        
        let newsender = data[4 ..< 8]
        let newreceiver = data[8 ..< 12]
        let newephemeralKey=data[12 ..< 44]
        let newempty=data[44 ..< 60]
        let newmac1=data[60 ..< 76]
        let newmac2=data[76 ..< 92]

        self.init(sender: newsender, receiver: newreceiver, ephemeralKey: newephemeralKey, empty: newempty, mac1: newmac1, mac2: newmac2, oldState: initiation.state)
    }
    
    public func encode() -> Data {
        return concat([type, reserved, sender, receiver, ephemeralKey, empty, mac1, mac2])
    }
}

public struct TransportDataMessage {
    let type: Data = Data(bytes: [0b00100000])
    let reserved: Data = Data(repeating: 0x00, count: 3)
    let receiver: Data
    let counter: Data
    let packet: Data
    var state: State
    
    public init(plainPacket: Data, initiation: HandshakeInitiation, response: HandshakeResponse) {
        state=response.state
        receiver=response.receiver
        
        let sodium=Sodium()
        var paddedPacket=plainPacket.array
        sodium.utils.pad(bytes: &paddedPacket, blockSize: 16)
        
        counter = state.nsendi
        packet = AEAD(key: state.tsendi!, counter: state.nsendi, plainText: Data(array: paddedPacket), authText: e)
        state.incrNsendi()
    }
    
    init(receiver: Data, counter: Data, packet: Data, oldState: State) {
        self.receiver=receiver
        self.counter=counter
        self.packet=packet
        self.state=oldState
    }
    
    public init(data: Data, initiator: Bool, sharedState: State, plainPacket: Data) {
        let newtype = data[0 ..< 1]
        
        assert(newtype == Data(bytes: [0b00100000]))
        
        let newreserved = data[1 ..< 4]
        
        assert(newreserved == Data(repeating: 0x00, count: 3))
        
        let newreceiver = data[4 ..< 8]
        let newcounter=data[8 ..< 16]
        let newpacket=data[16 ..< data.count]
        
        self.init(receiver: newreceiver, counter: newcounter, packet: newpacket, oldState: sharedState)
    }
    
    public func encode() -> Data {
        return concat([type, reserved, receiver, counter, packet])
    }
}

public struct CookieReply {
    let type: Data = Data(bytes: [0b11000000])
    let reserved: Data = Data(repeating: 0x00, count: 3)
    let receiver: Data
    let nonce: Data
    let cookie: Data
    var state: State
    
    public init(sharedState: State, receiver: Data, nonce: Data, cookie: Data) {
        self.state=sharedState
        self.receiver=receiver
        self.nonce=nonce
        self.cookie=cookie
        
        self.state.cookie=cookie
        self.state.cookieTimestamp=Date()
    }
    
    public init(data: Data, sharedState: State) {
        let newtype = data[0 ..< 1]
        
        assert(newtype == Data(bytes: [0b11000000]))
        
        let newreserved = data[1 ..< 4]
        
        assert(newreserved == Data(repeating: 0x00, count: 3))
        
        let newreceiver = data[4 ..< 8]
        let newnonce=data[8 ..< 32]
        let newcookie=data[32 ..< 64]
        
        self.init(sharedState: sharedState, receiver: newreceiver, nonce: newnonce, cookie: newcookie)
    }
}
