//
//  NonceTracker.swift
//  WireGuard
//
//  Created by Dr. Brandon Wiley on 10/17/18.
//

import Foundation

/*
 * https://www.wireguard.com/protocol/#nonce-reuse-replay-attacks
 
 * Nonce Reuse & Replay Attacks
 
   Nonces are never reused. A 64bit counter is used, and cannot be wound backward. UDP, however, sometimes delivers messages out of order. For that reason we use a sliding window, in which we keep track of the greatest counter received and a window of roughly 2000 prior values. This avoids replay attacks while ensuring nonces are never reused and that UDP can maintain out-of-order delivery performance.
 */
struct NonceTracker
{
    var greatest_counter: UInt64
    var seen: Set<UInt64>
}

extension NonceTracker
{
    mutating func add(counter: UInt64)
    {
        if counter > greatest_counter
        {
            greatest_counter = counter
        }
        
        seen.insert(counter)
    }
    
    mutating func expire()
    {
        guard greatest_counter >= 2000 else
        {
            return
        }
        
        seen = seen.filter
        {
            (member) -> Bool in
            
            member >= greatest_counter - 2000
        }
    }
    
    func nextCounter() -> UInt64
    {
        return greatest_counter + 1
    }
}
