//
//  CryptoShim.swift
//  WireGuard
//
//  Created by Brandon Wiley on 11/20/17.
//  Copyright © 2017 Operator Foundation. All rights reserved.
//

import Foundation

struct ChaCha20Poly1305 {
    let sharedKey: Data
    let nonce: Data
    
    init(sharedKey: Data, nonce: Data) {
        self.sharedKey=sharedKey
        self.nonce=nonce
    }
    
    func encrypt(data: Data) -> Data {
        return Data()
    }
}

func AEAD(key: Data, counter: Data, plainText: Data, authText: Data) -> Data {
    return Data()
}

func XAEAD(key: Data, nonce: Data, plainText: Data, authText: Data) -> Data {
    return Data()
}

func hash(data: Data) -> Data {
    return Data()
}

func hash(_ data1: Data, _ data2: Data) -> Data {
    var temp = Data()
    temp.append(data1)
    temp.append(data2)
    return hash(data: temp)
}

