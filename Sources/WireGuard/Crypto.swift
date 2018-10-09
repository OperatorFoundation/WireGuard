//
//  Crypto.swift
//  WireGuard
//
//  Created by Brandon Wiley on 11/25/17.
//  Copyright © 2017 Operator Foundation. All rights reserved.
//

import Foundation
import Sodium
import Blake2
import HKDFKit

let CONSTRUCTION: Data = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".data(using: .ascii)!
let IDENTIFIER: Data = "WireGuard v1 zx2c4 Jason@zx2c4.com".data(using: .ascii)!
let LABEL_MAC1: Data = "mac1----".data(using: .ascii)!
let labelCookie: Data = "cookie--".data(using: .ascii)!

func randomBytes(number: Int) -> Data? {
    var data = Data(count: number)

    for index in 0..<number
    {
        data[index] = UInt8.random(in: 0...255)
    }
    
    return data
}

func TAI64N() -> Data {
    let now = Date().timeIntervalSince1970
    var seconds: Int64 = Int64(now)
    var ns: Int32 = Int32((now - Double(seconds)) * 1000)
    let sdata = Data(buffer: UnsafeBufferPointer(start: &seconds, count: 8))
    let nsdata = Data(buffer: UnsafeBufferPointer(start: &ns, count: 4))
    
    var result = Data()
    result.append(sdata)
    result.append(nsdata)
    
    return result
}

public func DH_GENERATE() -> (privateKey: Data, publiKey: Data) {
    let sodium = Sodium()
    let keypair = sodium.box.keyPair()!
    return (Data(array: keypair.secretKey), Data(array: keypair.publicKey))
}

func DH(_ privateKey: Data, _ publicKey: Data, _ peerPublicKey: Data) -> Data {
    let sodium = Sodium()
    let result = sodium.keyExchange.sessionKeyPair(publicKey: publicKey.array, secretKey: privateKey.array, otherPublicKey: peerPublicKey.array, side: .CLIENT)!
    return Data(array: result.tx)
}

func blake2s(data: Data, key: Data) -> Data {
    let input: Data = data
    let keyData: Data = key

    return blake2Hash(input: input, key: keyData, outputlen: 32)
}

func MAC(key: Data, data: Data) -> Data {
    return blake2s(data: data, key: key)[0 ..< 16]
}

func HMAC(_ key: Data, _ data: Data) -> Data {
    return blake2s(data: data, key: key)
}

func KDF1(_ key: Data, _ data: Data) -> Data {
    let t0 = HMAC(key, data)
    return t0
}

func KDF2(key: Data, data: Data) -> (Data, Data) {
    let t0 = HMAC(key, data)
    let t1 = HMAC(t0, Data(bytes: [0b10000000]))

    // FIXME - This is clearly wrong, check the spec to fix it.
    deriveKey(seed: key, info: data, salt: Data(), outputSize: 32)
    
    return (t0, t1)
}

func KDF3(key: Data, data: Data) -> (Data, Data, Data) {
    let t0 = HMAC(key, data)
    let t1 = HMAC(t0, Data(bytes: [0b10000000]))
    
    var t2data = t1
    t2data.append(Data(bytes: [0b01000000]))
    let t2 = HMAC(t0, t2data)
    
    return (t0, t1, t2)
}

func HASH(_ input: Data) -> Data
{
    return blake2Hash(input: input, key: Data(), outputlen: 32)
}

func AEAD(_ key: Data, _ counter: Data, _ plainText: Data, _ authText: Data) -> Data {
    let sodium = Sodium()
    let nonce = Data()
    if let result = sodium.aead.chacha20poly1305ietf.encrypt(message: plainText.array, secretKey: key.array, nonce: nonce.array, additionalData: authText.array)
    {
        return Data(array: result)
    }
    else
    {
        return Data()
    }
}

extension Data
{
    static func ||(left: Data, right: Data) -> Data
    {
        return left + right
    }
}
