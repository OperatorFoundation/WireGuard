//
//  CryptoShim.swift
//  WireGuard
//
//  Created by Brandon Wiley on 11/20/17.
//  Copyright © 2017 Operator Foundation. All rights reserved.
//

import Foundation

let construction: Data = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".data(using: .ascii)!
let identifier: Data = "WireGuard v1 zx2c4 Jason@zx2c4.com".data(using: .ascii)!
let labelMac1: Data = "mac1----".data(using: .ascii)!
let labelCookie: Data = "cookie--".data(using: .ascii)!

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

func TAI64N() -> Data {
    return Data()
}

struct Curve25519 {
    let publicKey: Data
    let privateKey: Data
    
    init(publicKey: Data, privateKey: Data) {
        self.publicKey=publicKey
        self.privateKey=privateKey
    }
    
    func sharedKey(peerPublicKey: Data) -> Data {
        return DH(privateKey: self.privateKey, publicKey: peerPublicKey)
    }
}

func newKeypair() -> Curve25519 {
    let (prv, pub) = DHgenerate()
    return Curve25519(publicKey: pub, privateKey: prv)
}

func MAC(key: Data, data: Data) -> Data {
    return Data()
}

func DH(privateKey: Data, publicKey: Data) -> Data {
    return Data()
}

public func DHgenerate() -> (privateKey: Data, publiKey: Data) {
    return (Data(), Data())
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

func HMAC(key: Data, data: Data) -> Data {
    return Data()
}

func KDF1(_ key: Data, _ data: Data) -> Data {
    return Data()
}

func KDF2(key: Data, data: Data) -> (Data, Data) {
    return (Data(), Data())
}

func KDF3(key: Data, data: Data) -> (Data, Data, Data) {
    return (Data(), Data(), Data())
}

func makeTimestamp() -> Data {
    return Data()
}

func randomBytes(number: Int) -> Data {
    return Data(repeating: 0x00, count: number)
}
