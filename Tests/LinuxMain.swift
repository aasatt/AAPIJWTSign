import XCTest

import JWTSignTests

var tests = [XCTestCaseEntry]()
tests += JWTSignTests.allTests()
XCTMain(tests)
