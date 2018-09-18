import XCTest
@testable import WireGuard

final class WireGuardTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(WireGuard().text, "Hello, World!")
    }


    static var allTests = [
        ("testExample", testExample),
    ]
}
