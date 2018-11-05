////
////  WireGuardTests.swift
////  WireGuardTests
////
////  Created by Brandon Wiley on 11/20/17.
////  Copyright © 2017 Operator Foundation. All rights reserved.
////
//
import XCTest
import Network
import Transport
import INI

@testable import WireGuard

class WireGuardTests: XCTestCase
{
    var privateKey: Data = Data()
    var publicKey: Data = Data()
    var testIPString: String = ""
    var portUInt: UInt16 = 9002
    var ephemeralPublic: Data = Data()
    var ephemeralPrivate: Data = Data()

    override func setUp()
    {
        super.setUp()

        do
        {
            let config = try parseINI(filename: "/Users/Lita/tempWireGuard/utun9.conf")
            
            print(config.sections)
            
            guard let privKeyString = config["Interface"]?["PrivateKey"]
            else
            {
                print("Unable to get private key from config file.")
                return
            }
            
            guard let pubKeyString = config["Peer"]?["PublicKey"]
            else
            {
                print("Unable to get public key from config file.")
                return
            }
            
            guard let endpointString = config["Peer"]?["Endpoint"]
            else
            {
                print("Unable to get endpoint from config file.")
                return
            }
            
            let endpointArray = endpointString.components(separatedBy: ":")
            let ephemeralKeys = DH_GENERATE()

            ephemeralPublic = ephemeralKeys.publiKey
            ephemeralPrivate = ephemeralKeys.privateKey
            portUInt = UInt16(string: endpointArray[1])
            testIPString = endpointArray[0]
            privateKey = Data(base64Encoded: privKeyString)!
            publicKey = Data(base64Encoded: pubKeyString)!
        }
        catch (let error)
        {
            print("Error reading config file: \(error)")
        }
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testInitiation()
    {
        var initiator = State(ephemeral_private: ephemeralPrivate,
                              ephemeral_public: ephemeralPublic,
                              static_private: privateKey,
                              static_public: publicKey,
                              ip_address: testIPString.data,
                              last_received_cookie: nil,
                              cookie_timestamp: nil)
        let initiation = HandshakeInitiation(initiator: &initiator, responder_static_public: publicKey, maybeStaticKey: Data(repeating: 0, count: 32))
        
        let initData = initiation?.encode()
        
        XCTAssertNotNil(initiation)
    }
    
//    func testListener()
//    {
//        let godot = expectation(description: "Waiting for...")
//        do
//        {
//            let listener = try NWListener(using: .udp, on: NWEndpoint.Port(rawValue: 7717)!)
//            listener.newConnectionHandler =
//                {
//                    [weak self] (newConnection) in
//
//
//
//                    if let strongSelf = self
//                    {
//                        print("\nNew connection = \(newConnection)\n")
//                    }
//            }
//
//            listener.start(queue: DispatchQueue(label: "test"))
//
//        }
//        catch (let error)
//        {
//            print("\nListener creation error: \(error)\n")
//            XCTFail()
//        }
//
//        wait(for: [godot], timeout: 3000)
//    }
    
    func testNetworkUDPConnection()
    {
        guard let port = NWEndpoint.Port(rawValue: portUInt)
        else
        {
            print("Unable to resolve port for test")
            XCTFail()
            return
        }

        guard let ipv4Address = IPv4Address(testIPString)
            else
        {
            print("Unable to resolve ipv4 address for test")
            XCTFail()
            return
        }
        
        let connected = expectation(description: "Connected to the server.")
        let host = NWEndpoint.Host.ipv4(ipv4Address)
        let connectionFactory = NetworkConnectionFactory(host: host, port: port)
        let maybeConnection = connectionFactory.connect(using: .udp)
        
        XCTAssertNotNil(maybeConnection)
        
        guard var connection = maybeConnection
            else
        {
            return
        }
        
        connection.stateUpdateHandler =
            {
                (newState) in
                
                print("CURRENT STATE = \(newState))")
                
                switch newState
                {
                case .ready:
                    print("\n🚀 open() called on tunnel connection  🚀\n")
                    connected.fulfill()
                    
                case .cancelled:
                    print("\n🙅‍♀️  Connection Canceled  🙅‍♀️\n")
                    
                case .failed(let error):
                    print("\n🐒💨  Connection Failed  🐒💨\n")
                    print("⛑  Failure Error: \(error.localizedDescription)")
                    XCTFail()
                    
                default:
                    print("\n🤷‍♀️  Unexpected State: \(newState))  🤷‍♀️\n")
                }
        }
        
        maybeConnection?.start(queue: DispatchQueue(label: "TestQueue"))
        
        waitForExpectations(timeout: 20)
        { (maybeError) in
            if let error = maybeError
            {
                print("Expectation completed with error: \(error.localizedDescription)")
            }
        }
    }
    
    func testNetworkUDPConnectionSendReceive()
    {
        guard let port = NWEndpoint.Port(rawValue: portUInt)
            else
        {
            print("Unable to resolve port for test")
            XCTFail()
            return
        }
        
        guard let ipv4Address = IPv4Address(testIPString)
            else
        {
            print("Unable to resolve ipv4 address for test")
            XCTFail()
            return
        }
        
        let connected = expectation(description: "Connected to the server.")
        let wrote = expectation(description: "Wrote data to the server.")
        let read = expectation(description: "Read data from the server.")
        let host = NWEndpoint.Host.ipv4(ipv4Address)
        let connectionFactory = NetworkConnectionFactory(host: host, port: port)
        let maybeConnection = connectionFactory.connect(using: .udp)
        
        XCTAssertNotNil(maybeConnection)
        
        guard var connection = maybeConnection
            else
        {
            return
        }
        
        connection.stateUpdateHandler =
        {
            (newState) in
            
            print("CURRENT STATE = \(newState))")
            
            switch newState
            {
            case .ready:
                print("\n🚀 open() called on tunnel connection  🚀\n")
                connected.fulfill()
                
                var initiator = State(ephemeral_private: self.ephemeralPrivate,
                                      ephemeral_public: self.ephemeralPublic,
                                      static_private: self.privateKey,
                                      static_public: self.publicKey,
                                      ip_address: self.testIPString.data,
                                      last_received_cookie: nil,
                                      cookie_timestamp: nil)
                
                let initiation = HandshakeInitiation(initiator: &initiator,
                                                     responder_static_public: self.publicKey,
                                                     maybeStaticKey: Data(repeating: 0, count: 32))
                
                let initData = initiation?.encode()
                
                connection.send(content: initData,
                                contentContext: .defaultMessage,
                                isComplete: true,
                                completion: NWConnection.SendCompletion.contentProcessed(
                {
                    (error) in

                    if error == nil
                    {
                        wrote.fulfill()
                        print("\nNo ERROR\n")
                    }

                    else
                    {
                        print("\n⛑  RECEIVED A SEND ERROR: \(String(describing: error))\n")
                        XCTFail()
                    }
                    
                    connection.receive(completion:
                    {
                        (maybeData, maybeContext, connectionComplete, maybeError) in
                        
                        print("\nTo receive is also nice.")
                        print("Data? \(String(describing: maybeData))")
                        if let data = maybeData
                        {
                            let responseString = String(data: data, encoding: .ascii)
                            print("Data to String? \(responseString!)")
                        }
                        print("Context? \(String(describing: maybeContext))")
                        print("Connection Complete? \(String(describing: connectionComplete))")
                        print("\n⛑  Error? \(maybeError.debugDescription)\n")
                        
                        if maybeError != nil
                        {
                            switch maybeError!
                            {
                            case .posix(let posixError):
                                print("\n⛑  Received a posix error: \(posixError)")
                            case .tls(let tlsError):
                                print("\n⛑  Received a tls error: \(tlsError)")
                            case .dns(let dnsError):
                                print("\n⛑  Received a dns error: \(dnsError)")
                            }
                            
                            XCTFail()
                        }
                        
                        if let data = maybeData
                        {
                            print("\nReceived some datas: \(data)\n")
                            read.fulfill()
                            
                            connection.stateUpdateHandler = nil
                        }
                    })
                }))
 
            case .cancelled:
                print("\n🙅‍♀️  Connection Canceled  🙅‍♀️\n")
                
            case .failed(let error):
                print("\n🐒💨  Connection Failed  🐒💨\n")
                print("⛑  Failure Error: \(error.localizedDescription)")
                XCTFail()
                
            default:
                print("\n🤷‍♀️  Unexpected State: \(newState))  🤷‍♀️\n")
            }
        }
        
        maybeConnection?.start(queue: DispatchQueue(label: "TestQueue"))
        
        waitForExpectations(timeout: 20)
        { (maybeError) in
            if let error = maybeError
            {
                print("Expectation completed with error: \(error.localizedDescription)")
            }
        }
    }
    
    //MARK: Crypto Tests
    
    func testTAI64N()
    {
        let encryptedTimestamp = TAI64N()
        XCTAssert(encryptedTimestamp.count == 12)
    }
}
