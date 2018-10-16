//
//  State.swift
//  WireGuard
//
//  Created by Brandon Wiley on 11/20/17.
//  Copyright © 2017 Operator Foundation. All rights reserved.
//

import Foundation
import Sodium

public struct State
{
    //Ephemeral Public Key
    var ephemeral_public: Data
    
    //Ephemeral Private Key
    var ephemeral_private: Data
    
    //Static Public Key
    var static_public: Data
    
    //Static Private Key
    var static_private: Data
    
    var sender_index: Int
    var ip_address: Data
    
    var chaining_key: Data?
    var hash: Data?
    var last_received_cookie: Data?
    var cookie_timestamp: Date?
    var changing_secret_every_two_minutes: Data?
    var sending_key: Data?
    var sending_key_counter: Int?
    var receiving_key: Data?
    var receiving_key_counter: Int?

    public init(ephemeral_private: Data,
                ephemeral_public: Data,
                static_private: Data,
                static_public: Data,
                ip_address: Data,
                sender_index: Int? = 0,
                last_received_cookie: Data?,
                cookie_timestamp: Date?)
    {
        self.ephemeral_private = ephemeral_private
        self.ephemeral_public = ephemeral_public
        self.static_private = static_private
        self.static_public = static_public
        self.ip_address = ip_address
        self.last_received_cookie = last_received_cookie
        self.cookie_timestamp = cookie_timestamp
    }
    
    mutating func incrNsendi() {
        
    }
    
    mutating func incrNsendr() {
        
    }

}
