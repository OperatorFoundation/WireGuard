import XCTest

import WireGuardTests

var tests = [XCTestCaseEntry]()
tests += WireGuardTests.allTests()
XCTMain(tests)