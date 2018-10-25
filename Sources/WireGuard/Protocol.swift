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

enum MessageType: UInt8
{
    case HandshakeInitiation = 1
    case HandshakeResponse = 2
    case CookieReply = 3
    case TransportData = 4
}

/**
 https://www.wireguard.com/protocol/#first-message-initiator-to-responder
 
 First Message: Initiator to Responder.
 The initiator sends this message.
 
 - property message_type: UInt8
 - property reserved_zero: Data, 3 bytes
 - property sender_index: UInt32
 - property unencrypted_ephemeral: Data, 32 bytes
 - property encrypted_static: Data, 32 bytes
 - property encrypted_timestamp: Data, 28 bytes
 - property mac1: Data, 16 bytes
 - property mac2: Data, 16 bytes
 */
public struct HandshakeInitiation
{
    let message_type: UInt8
    let reserved_zero: Data
    let sender_index: UInt32
    let unencrypted_ephemeral: Data
    let encrypted_static: Data
    let encrypted_timestamp: Data
    let mac1: Data
    let mac2: Data

    /**
     */
    public init?(initiator: inout State, responder_static_public: Data, maybeStaticKey: Data?)
    {
        // FIXME: Parameter was previously responder: State
        
        DatableConfig.endianess = .little

        // initiator.chaining_key = HASH(CONSTRUCTION)
        initiator.chaining_key = HASH(CONSTRUCTION)
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        initiator.hash = HASH(HASH(initiator.chaining_key! || IDENTIFIER) || responder_static_public)
        
        //initiator.ephemeral_private = DH_GENERATE()
        let ephemeralKeys = DH_GENERATE()
        initiator.ephemeral_private = ephemeralKeys.privateKey
        initiator.ephemeral_public = ephemeralKeys.publiKey

        // msg.message_type = 1
        message_type = MessageType.HandshakeInitiation.rawValue
        // msg.reserved_zero = { 0, 0, 0 }
        reserved_zero = Data(repeating: 0, count: 3)
        // msg.sender_index = little_endian(initiator.sender_index)
        sender_index = initiator.sender_index

        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        unencrypted_ephemeral = initiator.ephemeral_public
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        initiator.hash = HASH(initiator.hash! || unencrypted_ephemeral)

        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        var temp = HMAC(initiator.chaining_key!, unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        initiator.chaining_key = HMAC(temp, 0x1.data)

        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        temp = HMAC(initiator.chaining_key!, DH(initiator.ephemeral_private, initiator.ephemeral_public, responder_static_public))
        
        // initiator.chaining_key = HMAC(temp, 0x1)
        initiator.chaining_key = HMAC(temp, 0x1.data)
        
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        var key = HMAC(temp, initiator.chaining_key! || 0x2.data)
        
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        encrypted_static = AEAD(key, 0.data, initiator.static_public, initiator.hash!)

        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        initiator.hash = HASH(initiator.hash! || encrypted_static)
        
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        temp = HMAC(initiator.chaining_key!, DH(initiator.static_private, initiator.static_public, responder_static_public))
        
        // initiator.chaining_key = HMAC(temp, 0x1)
        initiator.chaining_key = HMAC(temp, 0x1.data)
        
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        key = HMAC(temp, initiator.chaining_key! || 0x2.data)
        
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        encrypted_timestamp = AEAD(key, 0.data, TAI64N(), initiator.hash!)
        
        guard encrypted_timestamp.count == 28
        else
        {
            print("\nUnable to initialize HandshakeInitiation: encrypted_timestamp is \(encrypted_timestamp.count) bytes, but must be 28 bytes\n")
            return nil
        }

        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        initiator.hash = HASH(initiator.hash! || encrypted_timestamp)
        
        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        DatableConfig.endianess = .little
        let payload1 = concat([message_type.data, reserved_zero, sender_index.data, unencrypted_ephemeral, encrypted_static, encrypted_timestamp])
        mac1 = MAC(key: HASH(LABEL_MAC1 || responder_static_public), data: payload1)
        
        guard mac1.count == 16
            else
        {
            print("\nUnable to initialize HandshakeInitiation: mac1 was not 16 bytes.\n")
            return nil
        }
        
        // if (initiator.last_received_cookie is empty or expired)
        // msg.mac2 = [zeros]
        // else
        // msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])

        if let cookie = initiator.last_received_cookie, let timestamp = initiator.cookie_timestamp, timestamp.timeIntervalSinceNow < 120
        {
            let payload2 = concat([payload1, mac1])
            mac2 = MAC(key: cookie, data: payload2)
            
            guard mac2.count == 16
                else
            {
                print("\nUnable to initialize HandshakeInitiation: mac2 was not 16 bytes.\n")
                return nil
            }
        }
        else
        {
            mac2 = Data(repeating: 0, count: 16)
        }
    }
    
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
    
    public func encode() -> Data
    {
        return concat([message_type.data, reserved_zero, sender_index.data , unencrypted_ephemeral, encrypted_static, encrypted_timestamp, mac1, mac2])
    }
}

func concat(_ items: [Data]) -> Data
{
    var temp = Data()
    for item in items
    {
        temp.append(item)
    }
    
    return temp
}

extension HandshakeInitiation: Equatable
{
    public static func == (lhs: HandshakeInitiation, rhs: HandshakeInitiation) -> Bool
    {
        return
            lhs.sender_index == rhs.sender_index &&
            lhs.unencrypted_ephemeral == rhs.unencrypted_ephemeral &&
            lhs.encrypted_static == rhs.encrypted_static &&
            lhs.encrypted_timestamp == rhs.encrypted_timestamp &&
            lhs.mac1 == rhs.mac1 &&
            lhs.mac2 == rhs.mac2
    }
}

/**
 https://www.wireguard.com/protocol/#second-message-responder-to-initiator
 
 Second Message: responder to initiator
 
 The responder sends this message, after processing the handshake request and applying the same operations to arrive at an identical state.
 
 - property message_type: UInt8
 - property reserved_zero: Data
 - property sender_index: UInt32
 - property receiver_index: UInt32
 - property unencrypted_ephemeral: Data, should be 32 bytes
 - property encrypted_nothing: Data
 - property mac1: Data
 - property mac2: Data
 */

public struct HandshakeResponse
{
    let message_type: UInt8
    let reserved_zero: Data
    let sender_index: UInt32
    let receiver_index: UInt32
    let unencrypted_ephemeral: Data //Should be 32 bytes
    let encrypted_nothing: Data
    let mac1: Data
    let mac2: Data
    
    /**
     When the initiator receives this message, it decrypts and does all the above operations in reverse, so that the state is identical.
     */
    public init?(initiator: State, responder: inout State, preshared_key: Data)
    {
        // responder.ephemeral_private = DH_GENERATE()
        let ephemeralKeys = DH_GENERATE()

        guard ephemeralKeys.privateKey.count == 32, ephemeralKeys.publiKey.count == 32
        else
        {
            print("Unable to initialize HandshakeResponse: ephemeral private key was not 32 bytes.")
            return nil
        }
        
        responder.ephemeral_private = ephemeralKeys.privateKey
        responder.ephemeral_public = ephemeralKeys.publiKey
        
        // msg.message_type = 2
        message_type = MessageType.HandshakeResponse.rawValue
        
        // msg.reserved_zero = { 0, 0, 0 }
        reserved_zero = Data(repeating: 0, count: 3)
        
        // msg.sender_index = little_endian(responder.sender_index)
        sender_index = responder.sender_index
        
        // msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index = initiator.sender_index
        
        // msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
        unencrypted_ephemeral = responder.ephemeral_private
        
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        guard let responderHash = responder.hash
        else
        {
            print("Unable to initialize handshake response: Provided responder hash is nil.")
            return nil
        }
        
        responder.hash = HASH(responderHash || unencrypted_ephemeral)
        
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        guard let responderChainingKey = responder.chaining_key
        else
        {
            print("Unable to initialize handshake response: provided responder chaining key is nil.")
            return nil
        }
        
        var temp = HMAC(responderChainingKey, unencrypted_ephemeral)
        
        // responder.chaining_key = HMAC(temp, 0x1)
        responder.chaining_key = HMAC(temp, 0x1.data)
        
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        temp = HMAC(responder.chaining_key!, DH(responder.ephemeral_private, responder.ephemeral_public, initiator.ephemeral_public))
        
        // responder.chaining_key = HMAC(temp, 0x1)
        responder.chaining_key = HMAC(temp, 0x1.data)
        
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        temp = HMAC(responder.chaining_key!, DH(responder.ephemeral_private, responder.ephemeral_public, initiator.static_public))
        
        // responder.chaining_key = HMAC(temp, 0x1)
        responder.chaining_key = HMAC(temp, 0x1.data)
        
        // temp = HMAC(responder.chaining_key, preshared_key)
        temp = HMAC(responder.chaining_key!, preshared_key)
        
        // responder.chaining_key = HMAC(temp, 0x1)
        responder.chaining_key = HMAC(temp, 0x1.data)
        
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        let temp2 = HMAC(temp, responder.chaining_key! || 0x2.data)
        
        //FIXME: Endianness
        // key = HMAC(temp, temp2 || 0x3)
        let key = HMAC(temp, temp2 || 0x3.data)
        
        // responder.hash = HASH(responder.hash || temp2)
        responder.hash = HASH(responder.hash! || temp2)
        
        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        encrypted_nothing = AEAD(key, Data(bytes: [0]), Data(), responder.hash!)
        
        // responder.hash = HASH(responder.hash || msg.encrypted_nothing)
        responder.hash = HASH(responder.hash! || encrypted_nothing)
        
        // msg.mac1 = MAC(HASH(LABEL_MAC1 || initiator.static_public), msg[0:offsetof(msg.mac1)])
        //FIXME
        DatableConfig.endianess = .little
        let payload1 = concat([message_type.data, reserved_zero, sender_index.data, unencrypted_ephemeral, encrypted_nothing])
        mac1 = MAC(key: HASH(LABEL_MAC1 || initiator.static_public), data: payload1)
        
        guard mac1.count == 16
        else
        {
            print("Unable to initialize HandshakeResponse: mac1 was not 16 bytes.")
            return nil
        }
        
        // if (responder.last_received_cookie is empty or expired)
        // msg.mac2 = [zeros]
        // else
        // msg.mac2 = MAC(responder.last_received_cookie, msg[0:offsetof(msg.mac2)])
        
        if let cookie = responder.last_received_cookie, let timestamp = responder.cookie_timestamp, timestamp.timeIntervalSinceNow < 120
        {
            let payload2 = concat([payload1, mac1])
            mac2 = MAC(key: cookie, data: payload2)
            
            guard mac2.count == 16
            else
            {
                print("Unable to initialize Handshake Response: mac2 was not 16 bytes.")
                return nil
            }
        }
        else
        {
            mac2 = Data(repeating: 0, count: 16)
        }
    }
    
    //FIXME: Public Init

//    public init(data: Data, initiation: HandshakeInitiation)
//    {
//        let newtype = data[0 ..< 1]
//
//        assert(newtype == Data(bytes: [0b01000000]))
//
//        let newreserved = data[1 ..< 4]
//
//        assert(newreserved == Data(repeating: 0x00, count: 3))
//
//        let newsender = data[4 ..< 8]
//        let newreceiver = data[8 ..< 12]
//        let newephemeralKey=data[12 ..< 44]
//        let newempty=data[44 ..< 60]
//        let newmac1=data[60 ..< 76]
//        let newmac2=data[76 ..< 92]
//
//        self.init(sender: newsender,
//                  receiver: newreceiver,
//                  ephemeralKey: newephemeralKey,
//                  empty: newempty,
//                  mac1: newmac1,
//                  mac2: newmac2,
//                  oldState: initiation.initiator /* Previously: initiation.responder */)
//    }
    
    public func encode() -> Data
    {
        return concat([message_type.data, reserved_zero, sender_index.data, receiver_index.data, unencrypted_ephemeral, encrypted_nothing, mac1, mac2])
    }
}

/**
 https://www.wireguard.com/protocol/#subsequent-messages-exchange-of-data-packets
 
 The initiator and the responder exchange this packet for sharing encapsulated packet data:
 
 - property message_type: UInt8
 - property reserved_zero: Data, 3 bytes
 - property receiver_index: UInt32
 - property counter: UInt64
 - property encrypted_encapsulated_packet: Data
 
 */
public struct TransportDataMessage
{
    let message_type: UInt8
    let reserved_zero: Data
    let receiver_index: UInt32
    let counter: UInt64
    let encrypted_encapsulated_packet: Data
    
    /**
     The fields are populated as follows:
     
     msg.message_type = 4
     msg.reserved_zero = { 0, 0, 0 }
     msg.receiver_index = little_endian(responder.sender_index)
     encapsulated_packet = encapsulated_packet || zero padding in order to make the length a multiple of 16
     counter = initiator.sending_key_counter++
     msg.counter = little_endian(counter)
     msg.encrypted_encapsulated_packet = AEAD(initiator.sending_key, counter, encapsulated_packet, [empty])
     
     The responder uses its responder.receiving_key to read the message.
     */
    public init?(responder: State, initiator: State, packet_data: Data)
    {
        ///msg.message_type = 4
        message_type = MessageType.TransportData.rawValue
        
        ///msg.reserved_zero = { 0, 0, 0 }
        reserved_zero = Data(repeating: 0, count: 3)
        
        ///msg.receiver_index = little_endian(responder.sender_index)
        receiver_index = responder.sender_index
        
        ///encapsulated_packet = encapsulated_packet || zero padding in order to make the length a multiple of 16
        var encapsulated_packet = packet_data
        
        if encapsulated_packet.count % 16 != 0
        {
            let paddingSize = 16 - (encapsulated_packet.count % 16)
            encapsulated_packet = encapsulated_packet || Data(repeating: 0, count: paddingSize)
        }
        
        ///counter = initiator.sending_key_counter++
        ///msg.counter = little_endian(counter)
        guard let initiatorSendingKeyCounter = initiator.sending_key_counter
        else
        {
            print("Unable to initialize TransportDataMessage: Initiator has nil sending_key_counter.")
            return nil
        }
        counter = initiatorSendingKeyCounter + 1
        
        ///msg.encrypted_encapsulated_packet = AEAD(initiator.sending_key, counter, encapsulated_packet, [empty])
        guard let initiatorSendingKey = initiator.sending_key
        else
        {
            print("Unable to initialize TransportDataMessage: Initiator sending_key is nil.")
            return nil
        }
        
        encrypted_encapsulated_packet = AEAD(initiatorSendingKey, counter.data, encapsulated_packet, Data())
    }

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
     - parameter responder: State, in this implementation, the server
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
        var temp2 = HMAC(temp1, 0x1.data)
        
        ///temp3 = HMAC(temp1, temp2 || 0x2)
        var temp3 = HMAC(temp1, temp2 || 0x2.data)
        
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
        temp2 = HMAC(temp1, 0x1.data)
        
        ///temp3 = HMAC(temp1, temp2 || 0x2)
        temp3 = HMAC(temp1, temp2 || 0x2.data)
        
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
        
        return true
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
 When a message with a valid msg.mac1 is received, but msg.mac2 is all zeros or invalid and the server is under load, the server may send a cookie reply packet
 
 - property message_type: UInt8
 - property reserved_zero: Data, 3 bytes
 - property receiver_index: UInt32
 - property nonce: Data, 24 bytes
 - property encrypted_cookie: Data, 16 bytes
 */
public struct CookieReply
{
    var message_type: UInt8
    var reserved_zero: Data
    var receiver_index: UInt32
    var nonce: Data
    var encrypted_cookie: Data
    
    public init?(initiator: State, responder: State, last_received_msg: HandshakeInitiation)
    {
        ///msg.message_type = 3
        message_type = MessageType.CookieReply.rawValue
        
        ///msg.reserved_zero = { 0, 0, 0 }
        reserved_zero = Data(repeating: 0, count: 3)
        
        ///msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index = initiator.sender_index
        
        ///msg.nonce = RAND(24)
        guard let random24 = randomBytes(number: 24), random24.count == 24
        else
        {
            print("Unable to initialize CookieReply: Unable to generate random data for nonce.")
            return nil
        }
        
        nonce = random24
        
        ///cookie = MAC(responder.changing_secret_every_two_minutes, initiator.ip_address)
        guard let changingSecretEveryTwoMinutes = responder.changing_secret_every_two_minutes
        else
        {
            print("Unable to initialize CookieReply: responder.changing_secret_every_two_minutes is nil.")
            return nil
        }
        
        let cookie = MAC(key: changingSecretEveryTwoMinutes, data: initiator.ip_address)
        
        ///msg.encrypted_cookie = XAEAD(HASH(LABEL_COOKIE || responder.static_public), msg.nonce, cookie, last_received_msg.mac1)
        encrypted_cookie = XAEAD(key: HASH(labelCookie || responder.static_public), nonce: nonce, plainText: cookie, authText: last_received_msg.mac1)
        
        guard encrypted_cookie.count == 16
        else
        {
            print("Unable to initiate CookieReply: encrypted_cookie is \(encrypted_cookie.count) bytes, but must be 16.")
            return nil
        }
    }

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
