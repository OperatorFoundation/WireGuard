//
//  Timers.swift
//  WireGuard
//
//  Created by Dr. Brandon Wiley on 10/17/18.
//

import Foundation

/*
 * https://www.wireguard.com/protocol/#connection-less-protocol
 
 * Connection-less Protocol
 
 Any secure protocol require some state to be kept, so there is an initial very simple handshake that establishes symmetric keys to be used for data transfer. This handshake occurs every few minutes, in order to provide rotating keys for perfect forward secrecy. It is done based on time, and not based on the contents of prior packets, because it is designed to deal gracefully with packet loss. There is a clever pulse mechanism to ensure that the latest keys and handshakes are up to date, renegotiating when needed, by automatically detecting when handshakes are out of date. It uses a separate packet queue per host, so that it can minimize packet loss during handshakes while providing steady performance for all clients.
 
 In other words, you bring the device up, and everything else is handled for you automatically. You don't need to worry about asking it to reconnect or disconnect or reinitialize, or anything of that nature.
 
 The following timers are at play:
 
 A handshake initiation is retried after REKEY_TIMEOUT + jitter ms, if a response has not been received, where jitter is some random value between 0 and 333 ms.
 If a packet has been received from a given peer, but we have not sent one back to the given peer in KEEPALIVE ms, we send an empty packet.
 If we have sent a packet to a given peer but have not received a packet after from that peer for (KEEPALIVE + REKEY_TIMEOUT) ms, we initiate a new handshake.
 All ephemeral private keys and symmetric session keys are zeroed out after (REJECT_AFTER_TIME * 3) ms if no new keys have been exchanged.
 After sending a packet, if the number of packets sent using that key exceed REKEY_AFTER_MESSAGES, we initiate a new handshake.
 After sending a packet, if the sender was the original initiator of the handshake and if the current session key is REKEY_AFTER_TIME ms old, we initiate a new handshake. If the sender was the original responder of the handshake, it does not reinitiate a new handshake after REKEY_AFTER_TIME ms like the original initiator does.
 After receiving a packet, if the receiver was the original initiator of the handshake and if the current session key is REKEY_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT ms old, we initiate a new handshake.
 Handshakes are only initiated once every REKEY_TIMEOUT ms, with this strict rate limiting enforced.
 Packets are dropped if the session counter is greater than REJECT_AFTER_MESSAGES or if its key is older than REJECT_AFTER_TIME.
 After REKEY_ATTEMPT_TIME ms of trying to initiate a new handshake, the retries give up and cease, and clear all existing packets queued up to be sent. If a packet is explicitly queued up to be sent, then this timer is reset.
 */

/*
 * From wireguard-go/constants.go:
 
 const (
     RekeyAfterMessages      = (1 << 64) - (1 << 16) - 1
     RejectAfterMessages     = (1 << 64) - (1 << 4) - 1
     RekeyAfterTime          = time.Second * 120
     RekeyAttemptTime        = time.Second * 90
     RekeyTimeout            = time.Second * 5
     MaxTimerHandshakes      = 90 / 5 /* RekeyAttemptTime / RekeyTimeout */
     RekeyTimeoutJitterMaxMs = 334
     RejectAfterTime         = time.Second * 180
     KeepaliveTimeout        = time.Second * 10
     CookieRefreshTime       = time.Second * 120
     HandshakeInitationRate  = time.Second / 20
     PaddingMultiple         = 16
 )
 */
struct Timers
{
    static let KEEPALIVE_TIMEOUT: UInt = 1000 * 10 // 10 seconds
    
    static let REJECT_AFTER_MESSAGES: UInt = (1 << 64) - (1 << 4) - 1 // 18446744073709551599
    static let REJECT_AFTER_TIME: UInt =  1000 * 180 // 180 seconds
    
    static let REKEY_AFTER_MESSAGES: UInt = (1 << 64) - (1 << 16) - 1 // 18446744073709486079
    static let REKEY_AFTER_TIME: UInt = 1000 * 120 // 120 seconds
    static let REKEY_ATTEMPT_TIME: UInt = 1000 * 90 // 90 seconds
    static let REKEY_TIMEOUT: UInt = 1000 * 5 // 5 seconds
}

enum TimerState
{
    case waiting
    case sent
    case received
}

extension Timers
{
    // A handshake initiation is retried after REKEY_TIMEOUT + jitter ms, if a response has not been received, where jitter is some random value between 0 and 333 ms.
    static func checkRetryHandshakeInitiation(elapsedTimeSinceHandshakeInitiation: UInt) -> Bool
    {
        let jitter = UInt.random(in: 0 ... 333)
        return elapsedTimeSinceHandshakeInitiation >= REKEY_TIMEOUT + jitter
    }
  
    // If a packet has been received from a given peer, but we have not sent one back to the given peer in KEEPALIVE ms, we send an empty packet.
    static func checkSendEmptyPacket(elapsedTimeSinceLastPacketSent: UInt) -> Bool
    {
        return elapsedTimeSinceLastPacketSent > KEEPALIVE_TIMEOUT
    }

    static func checkInitiateNewHandshake(elapsedTimeSinceHandshakeInitiation: UInt, elapsedTimeSinceLastPacketSent: UInt, packetsSent: UInt, state: TimerState, initiator: Bool) -> Bool
    {
        // Handshakes are only initiated once every REKEY_TIMEOUT ms, with this strict rate limiting enforced.
        guard elapsedTimeSinceHandshakeInitiation >= REKEY_TIMEOUT else
        {
            return false
        }
        
        switch(state)
        {
            // If we have sent a packet to a given peer but have not received a packet after from that peer for (KEEPALIVE + REKEY_TIMEOUT) ms, we initiate a new handshake.
            case .waiting:
                return elapsedTimeSinceLastPacketSent >= KEEPALIVE_TIMEOUT + REKEY_TIMEOUT
            
            case .sent:
                // After sending a packet, if the sender was the original initiator of the handshake and if the current session key is REKEY_AFTER_TIME ms old, we initiate a new handshake. If the sender was the original responder of the handshake, it does not reinitiate a new handshake after REKEY_AFTER_TIME ms like the original initiator does.
                if initiator && elapsedTimeSinceHandshakeInitiation >= REJECT_AFTER_TIME
                {
                    return true
                }
                
                // After sending a packet, if the number of packets sent using that key exceed REKEY_AFTER_MESSAGES, we initiate a new handshake.
                return packetsSent > REKEY_AFTER_MESSAGES
            
            // After receiving a packet, if the receiver was the original initiator of the handshake and if the current session key is REKEY_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT ms old, we initiate a new handshake.
            case .received:
                if initiator && elapsedTimeSinceHandshakeInitiation >= REKEY_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
                {
                    return true
                }
        }
        
        return false
    }
    
    // All ephemeral private keys and symmetric session keys are zeroed out after (REJECT_AFTER_TIME * 3) ms if no new keys have been exchanged.
    static func checkZeroKeys(elapsedTimeSinceKeyExchange: UInt) -> Bool
    {
        return elapsedTimeSinceKeyExchange >= REJECT_AFTER_TIME * 3
    }
    
    // Packets are dropped if the session counter is greater than REJECT_AFTER_MESSAGES or if its key is older than REJECT_AFTER_TIME.
    static func checkDropPacket(elapsedTimeSinceHandshakeInitiation: UInt, sessionCounter: UInt) -> Bool
    {
        return sessionCounter > REJECT_AFTER_MESSAGES || elapsedTimeSinceHandshakeInitiation > REJECT_AFTER_TIME
    }
    
    // After REKEY_ATTEMPT_TIME ms of trying to initiate a new handshake, the retries give up and cease, and clear all existing packets queued up to be sent. If a packet is explicitly queued up to be sent, then this timer is reset.
    static func checkKeepRetryingHandshake(elapsedTimeSinceHandshakeInitiation: UInt) -> Bool
    {
        return elapsedTimeSinceHandshakeInitiation < REKEY_ATTEMPT_TIME
    }
}
