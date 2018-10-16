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

/*
 * https://www.wireguard.com/protocol/
 
 First Message: Initiator to Responder
 
 The initiator sends this message:
 
 msg = handshake_initiation
 {
     u8 message_type
     u8 reserved_zero[3]
     u32 sender_index
     u8 unencrypted_ephemeral[32]
     u8 encrypted_static[AEAD_LEN(32)]
     u8 encrypted_timestamp[AEAD_LEN(12)]
     u8 mac1[16]
     u8 mac2[16]
 }
 
 */
public struct HandshakeInitiation {
    let message_type: UInt8
    let reserved_zero: Data
    let sender_index: Data
    let unencrypted_ephemeral: Data
    let encrypted_static: Data
    let encrypted_timestamp: Data
    let mac1: Data
    let mac2: Data
    var initiator: State = State()

    /*
     The fields are populated as follows:
     
     msg.message_type = 1
     msg.reserved_zero = { 0, 0, 0 }
     msg.sender_index = little_endian(initiator.sender_index)
     
     msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
     initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
     
     temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
     initiator.chaining_key = HMAC(temp, 0x1)
     
     temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
     initiator.chaining_key = HMAC(temp, 0x1)
     key = HMAC(temp, initiator.chaining_key || 0x2)
     
     msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
     initiator.hash = HASH(initiator.hash || msg.encrypted_static)
     
     temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
     initiator.chaining_key = HMAC(temp, 0x1)
     key = HMAC(temp, initiator.chaining_key || 0x2)
     
     msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
     initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
     
     msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
     if (initiator.last_received_cookie is empty or expired)
     msg.mac2 = [zeros]
     else
     msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
     */
    public init(spubr: Data, sprivi: Data, maybeStaticKey: Data?)
    {
        // 5.4.2
        // initiator.chaining_key = HASH(CONSTRUCTION)
        initiator.chaining_key = HASH(CONSTRUCTION)
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || spubr)
        
        //initiator.ephemeral_private = DH_GENERATE()
        let (eprivi, epubi) = DH_GENERATE()
        initiator.ephemeral_private = eprivi
        initiator.ephemeral_public = epubi

        // msg.message_type = 1
        message_type = 1
        // msg.reserved_zero = { 0, 0, 0 }
        reserved_zero = Data(repeating: 0x00, count: 3)
        // msg.sender_index = little_endian(initiator.sender_index)
        sender_index = initiator.sender_index

        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        unencrypted_ephemeral = initiator.ephemeral_public
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        initiator.hash = HASH(initiator.hash || unencrypted_ephemeral)

        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        var temp = HMAC(initiator.chaining_key, unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        initiator.chaining_key = HMAC(temp, Data(bytes: [0b10000000]))

        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, initiator.ephemeral_public, spubr))
        // initiator.chaining_key = HMAC(temp, 0x1)
        initiator.chaining_key = HMAC(temp, Data(bytes: [0b10000000]))
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        var key = HMAC(temp, initiator.chaining_key || Data(bytes: [0b01000000]))
        
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        encrypted_static = AEAD(key, Data(bytes: [0]), initiator.static_public, initiator.hash)
        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        initiator.hash = HASH(initiator.hash || encrypted_static)
        
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        temp = HMAC(initiator.chaining_key, DH(initiator.static_private, initiator.static_public, spubr))
        
        // initiator.chaining_key = HMAC(temp, 0x1)
        initiator.chaining_key = HMAC(temp, Data(bytes: [0b10000000]))
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        key = HMAC(temp, initiator.chaining_key || Data(bytes: [0b01000000]))
        
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        encrypted_timestamp = AEAD(key, Data(bytes: [0]), TAI64N(), initiator.hash)
        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        initiator.hash = HASH(initiator.hash || encrypted_timestamp)
        
        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        DatableConfig.endianess = .little
        let payload1 = concat([message_type.data, reserved_zero, sender_index, unencrypted_ephemeral, encrypted_static, encrypted_timestamp])
        mac1 = MAC(key: HASH(LABEL_MAC1 || spubr), data: payload1)
        
        // if (initiator.last_received_cookie is empty or expired)
        // msg.mac2 = [zeros]
        // else
        // msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])

        if let cookie = initiator.last_received_cookie, let timestamp = initiator.cookieTimestamp, timestamp.timeIntervalSinceNow < 120 {
            let payload2 = concat([payload1, mac1])
            mac2 = MAC(key: cookie, data: payload2)
        } else {
            mac2 = Data(repeating: 0, count: 16) // FIXME - different mac2 if cookies are present
        }
    }
    
//    init(sender: Data, ephemeralKey: Data, staticKey: Data, timestamp: Data, mac1: Data, mac2: Data, sprivr: Data, spubr: Data) {
//        self.sender_index=sender
//        self.unencrypted_ephemeral=ephemeralKey
//        self.encrypted_static=staticKey
//        self.encrypted_timestamp=timestamp
//        self.mac1=mac1
//        self.mac2=mac2
//
//        initiator.spubr=spubr
//        initiator.sprivr=sprivr
//        initiator.q=self.encrypted_static
//
//        // 5.4.2
//        initiator.chaining_key=HASH(data: CONSTRUCTION)
//        initiator.hash=HASH(initiator.chaining_key, IDENTIFIER)
//        initiator.hash=HASH(initiator.hi, initiator.spubr)
//        initiator.ephemeral_public = ephemeralKey
//        initiator.chaining_key = KDF1(initiator.chaining_key, initiator.ephemeral_public)
//
//        initiator.hi=hash(initiator.hi, staticKey)
//        let (tempci, k) = KDF2(key: initiator.chaining_key, data: DH(privateKey: initiator.sprivr, publicKey: initiator.spubr, peerPublicKey: initiator.spubi))
//        initiator.chaining_key = tempci
//        assert(timestamp == AEAD(key: k, counter: Data(repeating: 0, count: 8), plainText: TAI64N(), authText: initiator.hi))
//        initiator.hi = hash(initiator.hi, timestamp)
//
//        let payload1 = concat([message_type, reserved, sender, ephemeralKey, staticKey, timestamp])
//
//        let newmac1=MAC(key: hash(LABEL_MAC1, spubr), data: payload1)
//
//        assert(newmac1 == self.mac1)
//
//        let newmac2 = Data(repeating: 0, count: 16) // FIXME - different mac2 if cookies are present
//
//        assert(newmac2 == self.mac2)
//    }
    
//    public init(data: Data, sprivr: Data, spubr: Data) {
//        let newtype = data[0 ..< 1]
//        
//        assert(newtype == Data(bytes: [0b10000000]))
//        
//        let newreserved = data[1 ..< 4]
//        
//        assert(newreserved == Data(repeating: 0x00, count: 3))
//        
//        let newsender = data[4 ..< 8]
//        let newephemeralKey=data[8 ..< 40]
//        let newstaticKey=data[40 ..< 88]
//        let newtimestamp=data[88 ..< 116]
//        let newmac1=data[116 ..< 132]
//        let newmac2=data[132 ..< 148]
//        
//        self.init(sender: newsender, ephemeralKey: newephemeralKey, staticKey: newstaticKey, timestamp: newtimestamp, mac1: newmac1, mac2: newmac2, sprivr: sprivr, spubr: spubr)
//    }
    
    public func encode() -> Data {
        return concat([message_type.data, reserved_zero, sender_index , unencrypted_ephemeral, encrypted_static, encrypted_timestamp, mac1, mac2])
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
            lhs.sender_index == rhs.sender_index &&
            lhs.unencrypted_ephemeral == rhs.unencrypted_ephemeral &&
            lhs.encrypted_static == rhs.encrypted_static &&
            lhs.encrypted_timestamp == rhs.encrypted_timestamp &&
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
    var responder: State=State()
    
    init(sender: Data, receiver: Data, ephemeralKey: Data, empty: Data, mac1: Data, mac2: Data, oldState: State) {
        self.sender=sender
        self.receiver=receiver
        self.ephemeralKey=ephemeralKey
        self.empty=empty
        self.mac1=mac1
        self.mac2=mac2
        self.responder=oldState

        self.responder.epubr=ephemeralKey
        self.responder.cr=KDF1(self.responder.cr, self.responder.epubr)
        self.responder.hr=HASH(self.responder.hr || ephemeralKey)
        self.responder.cr = KDF1(self.responder.cr, DH(self.responder.eprivr,
                                                       self.responder.epubr,
                                                       self.responder.ephemeral_public))
        self.responder.cr = KDF1(self.responder.cr, DH(self.responder.eprivr,
                                                       self.responder.spubr,
                                                       self.responder.static_public))
        
        var t: Data
        var k: Data
        var tempcr: Data
        (tempcr, t, k) = KDF3(key: self.responder.cr, data: self.responder.q)
        self.responder.cr=tempcr
        self.responder.hr = HASH(self.responder.hr || t)
        assert(self.empty == AEAD(k, Data(repeating: 0, count: 8), e, self.responder.hr))
        self.responder.hr=HASH(self.responder.hr || empty)
        
        let payload = concat([type, reserved, sender, receiver, ephemeralKey, empty])
        
        let newmac1=MAC(key: HASH(LABEL_MAC1 || self.responder.static_public), data: payload)
        
        assert(newmac1 == mac1)
        
        let newmac2 = Data(repeating: 0, count: 16) // FIXME - different mac2 if cookies are present
        
        assert(newmac2 == mac2)
        
        responder.makeTransportKeys()
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

        self.init(sender: newsender,
                  receiver: newreceiver,
                  ephemeralKey: newephemeralKey,
                  empty: newempty,
                  mac1: newmac1,
                  mac2: newmac2,
                  oldState: initiation.initiator /* Previously: initiation.responder */)
    }
    
    public func encode() -> Data {
        return concat([type, reserved, sender, receiver, ephemeralKey, empty, mac1, mac2])
    }
}

/**
 https://www.wireguard.com/protocol/#subsequent-messages-exchange-of-data-packets
 */
public struct TransportDataMessage
{
    
//    let type: Data = Data(bytes: [0b00100000])
//    let reserved: Data = Data(repeating: 0x00, count: 3)
//    let receiver: Data
//    let counter: Data
//    let packet: Data
//    var state: State
//
//    public init(plainPacket: Data, initiation: HandshakeInitiation, response: HandshakeResponse)
//    {
//        state = response.responder
//        receiver = response.receiver
//
//        let sodium=Sodium()
//        var paddedPacket=plainPacket.array
//        sodium.utils.pad(bytes: &paddedPacket, blockSize: 16)
//
//        counter = state.sender_index
//        packet = AEAD(initiation.initiator.sending_key, state.sender_index, Data(array: paddedPacket), e)
//        state.incrNsendi()
//    }
//
//    init(receiver: Data, counter: Data, packet: Data, oldState: State)
//    {
//        self.receiver=receiver
//        self.counter=counter
//        self.packet=packet
//        self.state=oldState
//    }
//
//    public init(data: Data, initiator: Bool, sharedState: State, plainPacket: Data)
//    {
//        let newtype = data[0 ..< 1]
//
//        assert(newtype == Data(bytes: [0b00100000]))
//
//        let newreserved = data[1 ..< 4]
//
//        assert(newreserved == Data(repeating: 0x00, count: 3))
//
//        let newreceiver = data[4 ..< 8]
//        let newcounter=data[8 ..< 16]
//        let newpacket=data[16 ..< data.count]
//
//        self.init(receiver: newreceiver, counter: newcounter, packet: newpacket, oldState: sharedState)
//    }
//
//    public func encode() -> Data
//    {
//        return concat([type, reserved, receiver, counter, packet])
//    }
    
    /*
     * https://www.wireguard.com/protocol/#data-keys-derivation
     * Data Keys Derivation Section
     */
    /**
     After the handshake, keys are calculated by the initiator and responder for sending and receiving data, And then all previous chaining keys, ephemeral keys, and hashes are zeroed out.
     - parameter initiator: State, in this implementation of WireGuard this is the client
     - parameter responder: State, in this impplementation, the server
     - Returns: A boolean value indicating whether the keys were created successfully.
     */
    mutating func makeTransportKeys(initiator: inout State, responder: inout State) -> Bool
    {
        
        guard var initiator_chaining_key = initiator.chaining_key
        else
        {
            print("Attempted to make transport keys when initiator chaining key was nil.")
            return false
        }
        
        guard var responder_chaining_key = responder.chaining_key
        else
        {
            print("Attempted to make transport keys when the reponder chaining key was nil.")
            return false
        }
        
        // Initiator
        
        ///temp1 = HMAC(initiator.chaining_key, [empty])
        var temp1 = HMAC(initiator_chaining_key, Data())
            
        ///temp2 = HMAC(temp1, 0x1)
        //FIXME: Is this the correct binary value?
        var temp2 = HMAC(temp1, Data(bytes: [0b00100000]))
        
        ///temp3 = HMAC(temp1, temp2 || 0x2)
        var temp3 = HMAC(temp1, temp2 || Data(bytes: [0b01000000]))
        
        ///initiator.sending_key = temp2
        initiator.sending_key = temp2
        
        ///initiator.receiving_key = temp3
        initiator.receiving_key = temp3
        
        ///initiator.sending_key_counter = 0
        initiator.sending_key_counter = 0
        
        ///initiator.receiving_key_counter = 0
        initiator.receiving_key_counter = 0
        
        // Responder
        
        ///temp1 = HMAC(responder.chaining_key, [empty])
        temp1 = HMAC(responder_chaining_key, Data())
        
        ///temp2 = HMAC(temp1, 0x1)
        temp2 = HMAC(temp1, Data(bytes: [0b00100000]))
        
        ///temp3 = HMAC(temp1, temp2 || 0x2)
        temp3 = HMAC(temp1, temp2 || Data(bytes: [0b01000000]))
        
        ///responder.receiving_key = temp2
        responder.receiving_key = temp2
        
        ///responder.sending_key = temp3
        responder.sending_key = temp3
        
        ///responder.receiving_key_counter = 0
        responder.receiving_key_counter = 0
        
        ///responder.sending_key_counter = 0
        responder.sending_key_counter = 0
        
        zero(&initiator_chaining_key)
        zero(&initiator.ephemeral_public)
        zero(&initiator.ephemeral_private)
        zeroOptional(&initiator.chaining_key)
        zeroOptional(&initiator.hash)
        
        zero(&responder_chaining_key)
        zero(&responder.ephemeral_public)
        zero(&responder.ephemeral_private)
        zeroOptional(&responder.chaining_key)
        zeroOptional(&responder.hash)
    }
}

// Note: This is not guaranteed to be secure. This is probably the best we can do in Swift, which does not provide secure memory management.
func zeroOptional(_ data: inout Data?)
{
    guard data != nil
    else
    {
        return
    }
    
    for index in 0..<data!.count
    {
        data![index]=0
    }
}

func zero(_ data: inout Data)
{
    for index in 0..<data.count
    {
        data[index]=0
    }
}

/**
 https://www.wireguard.com/protocol/#dos-mitigation
 */
public struct CookieReply
{
//    let type: Data = Data(bytes: [0b11000000])
//    let reserved: Data = Data(repeating: 0x00, count: 3)
//    let receiver: Data
//    let nonce: Data
//    let cookie: Data
//    var state: State
//
//    public init(sharedState: State, receiver: Data, nonce: Data, cookie: Data) {
//        self.state=sharedState
//        self.receiver=receiver
//        self.nonce=nonce
//        self.cookie=cookie
//
//        self.state.last_received_cookie=cookie
//        self.state.cookie_timestamp = Date()
//    }
//
//    public init(data: Data, sharedState: State)
//    {
//        let newtype = data[0 ..< 1]
//
//        assert(newtype == Data(bytes: [0b11000000]))
//
//        let newreserved = data[1 ..< 4]
//
//        assert(newreserved == Data(repeating: 0x00, count: 3))
//
//        let newreceiver = data[4 ..< 8]
//        let newnonce=data[8 ..< 32]
//        let newcookie=data[32 ..< 64]
//
//        self.init(sharedState: sharedState, receiver: newreceiver, nonce: newnonce, cookie: newcookie)
//    }
}
