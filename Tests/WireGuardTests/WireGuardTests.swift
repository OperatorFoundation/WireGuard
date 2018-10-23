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

@testable import WireGuard

class WireGuardTests: XCTestCase
{
    func testListener()
    {
        let godot = expectation(description: "Waiting for...")
        do
        {
            let listener = try NWListener(using: .udp, on: NWEndpoint.Port(rawValue: 7717)!)
            listener.newConnectionHandler =
            {
                [weak self] (newConnection) in
                
                
                
                if let strongSelf = self
                {
                    print("\nNew connection = \(newConnection)\n")
                }
            }
            
            listener.start(queue: DispatchQueue(label: "test"))
            
        }
        catch (let error)
        {
            print("\nListener creation error: \(error)\n")
            XCTFail()
        }
        
        wait(for: [godot], timeout: 3000)
    }
}
//{
//    let fileManager = FileManager.default
//    var configURL: URL?
//    var privateKey: Data?
//    var publicKey: Data?
//    let testIPString: String?
//    let portUInt: UInt16?
//
//    var spubr: Data?
//    var sprivr: Data?
//    var spubi: Data?
//    var sprivi: Data?
//
//    override func setUp()
//    {
//        super.setUp()
//
//        guard let resourcePath = Bundle.main.path(forResource: "utun9", ofType: "conf")
//            else
//        {
//            print("Unable to find Default Config files.")
//            return
//        }
//
//        let resourceURL = URL(fileURLWithPath: resourcePath)
//        configURL = resourceURL
//
//        do
//        {
//            let configString = try String(contentsOf: configURL, encoding: .ascii)
//        }
//        catch (let error)
//        {
//            print("Error reading config file: \(error)")
//        }
//
//
//        var pub: Data
//        var priv: Data
//
//        (pub, priv) = DH_GENERATE()
//        spubr=pub
//        sprivr=priv
//
//        (pub, priv) = DH_GENERATE()
//        spubi=pub
//        sprivi=priv
//    }
//    
//    override func tearDown() {
//        super.tearDown()
//    }
//    
//    func testInitiation() {
//        //let initiation = HandshakeInitiation(hInitiator: <#T##State#>, responder: <#T##State#>, maybeStaticKey: <#T##Data?#>)
//            //HandshakeInitiation(spubr: spubr!, sprivi: sprivi!, maybeStaticKey: nil)
//       
//        
//        //let initData=initiation.encode()
//    }
//    
//    func testNetworkUDPConnection()
//    {
//        guard let port = NWEndpoint.Port(rawValue: portUInt)
//        else
//        {
//            print("Unable to resolve port for test")
//            XCTFail()
//            return
//        }
//
//        //        guard let ipv4Address = IPv4Address("172.217.9.174") //Google
//        guard let ipv4Address = IPv4Address(testIPString)
//            else
//        {
//            print("Unable to resolve ipv4 address for test")
//            XCTFail()
//            return
//        }
//        
//        let connected = expectation(description: "Connected to the server.")
//        let host = NWEndpoint.Host.ipv4(ipv4Address)
//        let connectionFactory = NetworkConnectionFactory(host: host, port: port)
//        let maybeConnection = connectionFactory.connect(using: .udp)
//        
//        XCTAssertNotNil(maybeConnection)
//        
//        guard var connection = maybeConnection
//            else
//        {
//            return
//        }
//        
//        connection.stateUpdateHandler =
//            {
//                (newState) in
//                
//                print("CURRENT STATE = \(newState))")
//                
//                switch newState
//                {
//                case .ready:
//                    print("\n🚀 open() called on tunnel connection  🚀\n")
//                    connected.fulfill()
//                    
//                case .cancelled:
//                    print("\n🙅‍♀️  Connection Canceled  🙅‍♀️\n")
//                    
//                case .failed(let error):
//                    print("\n🐒💨  Connection Failed  🐒💨\n")
//                    print("⛑  Failure Error: \(error.localizedDescription)")
//                    XCTFail()
//                    
//                default:
//                    print("\n🤷‍♀️  Unexpected State: \(newState))  🤷‍♀️\n")
//                }
//        }
//        
//        maybeConnection?.start(queue: DispatchQueue(label: "TestQueue"))
//        
//        waitForExpectations(timeout: 20)
//        { (maybeError) in
//            if let error = maybeError
//            {
//                print("Expectation completed with error: \(error.localizedDescription)")
//            }
//        }
//    }
//    
//    func testNetworkUDPConnectionSendReceive()
//    {
//        guard let port = NWEndpoint.Port(rawValue: portUInt)
//            else
//        {
//            print("Unable to resolve port for test")
//            XCTFail()
//            return
//        }
//        
//        //        guard let ipv4Address = IPv4Address("172.217.9.174") //Google
//        guard let ipv4Address = IPv4Address(testIPString)
//            else
//        {
//            print("Unable to resolve ipv4 address for test")
//            XCTFail()
//            return
//        }
//        
//        let connected = expectation(description: "Connected to the server.")
//        let wrote = expectation(description: "Wrote data to the server.")
//        let read = expectation(description: "Read data from the server.")
//        let host = NWEndpoint.Host.ipv4(ipv4Address)
//        let connectionFactory = NetworkConnectionFactory(host: host, port: port)
//        let maybeConnection = connectionFactory.connect(using: .udp)
//        
//        XCTAssertNotNil(maybeConnection)
//        
//        guard var connection = maybeConnection
//            else
//        {
//            return
//        }
//        
//        connection.stateUpdateHandler =
//        {
//            (newState) in
//            
//            print("CURRENT STATE = \(newState))")
//            
//            switch newState
//            {
//            case .ready:
//                print("\n🚀 open() called on tunnel connection  🚀\n")
//                connected.fulfill()
//                
////                let initiation = HandshakeInitiation(spubr: self.spubr!, sprivi: self.sprivi!, maybeStaticKey: nil)
////                let initData = initiation.encode()
////                connection.send(content: initData,
////                                contentContext: .defaultMessage,
////                                isComplete: true,
////                                completion: NWConnection.SendCompletion.contentProcessed(
////                {
////                    (error) in
////                    
////                    if error == nil
////                    {
////                        wrote.fulfill()
////                        print("\nNo ERROR\n")
////                    }
////                        
////                    else
////                    {
////                        print("\n⛑  RECEIVED A SEND ERROR: \(String(describing: error))\n")
////                        XCTFail()
////                    }
////                }))
//                    
//                connection.receive(completion:
//                {
//                    (maybeData, maybeContext, connectionComplete, maybeError) in
//                    
//                    print("\nTo receive is also nice.")
//                    print("Data? \(String(describing: maybeData))")
//                    if let data = maybeData
//                    {
//                        let responseString = String(data: data, encoding: .ascii)
//                        print("Data to String? \(responseString!)")
//                    }
//                    print("Context? \(String(describing: maybeContext))")
//                    print("Connection Complete? \(String(describing: connectionComplete))")
//                    print("\n⛑  Error? \(maybeError.debugDescription)\n")
//                    
//                    if maybeError != nil
//                    {
//                        switch maybeError!
//                        {
//                        case .posix(let posixError):
//                            print("\n⛑  Received a posix error: \(posixError)")
//                        case .tls(let tlsError):
//                            print("\n⛑  Received a tls error: \(tlsError)")
//                        case .dns(let dnsError):
//                            print("\n⛑  Received a dns error: \(dnsError)")
//                        }
//                        
//                        XCTFail()
//                    }
//                    
//                    if let data = maybeData
//                    {
//                        print("Received some datas: \(data)\n")
//                        read.fulfill()
//                        
//                        connection.stateUpdateHandler = nil
//                    }
//                })
//                    
//            case .cancelled:
//                print("\n🙅‍♀️  Connection Canceled  🙅‍♀️\n")
//                
//            case .failed(let error):
//                print("\n🐒💨  Connection Failed  🐒💨\n")
//                print("⛑  Failure Error: \(error.localizedDescription)")
//                XCTFail()
//                
//            default:
//                print("\n🤷‍♀️  Unexpected State: \(newState))  🤷‍♀️\n")
//            }
//        }
//        
//        maybeConnection?.start(queue: DispatchQueue(label: "TestQueue"))
//        
//        waitForExpectations(timeout: 20)
//        { (maybeError) in
//            if let error = maybeError
//            {
//                print("Expectation completed with error: \(error.localizedDescription)")
//            }
//        }
//    }
//}
