# TheKeyOAuthSwift

[![CI Status](https://img.shields.io/travis/ryan.t.carlson@cru.org/TheKeyOAuthSwift.svg?style=flat)](https://travis-ci.org/ryan.t.carlson@cru.org/TheKeyOAuthSwift)
[![Version](https://img.shields.io/cocoapods/v/TheKeyOAuthSwift.svg?style=flat)](https://cocoapods.org/pods/TheKeyOAuthSwift)
[![License](https://img.shields.io/cocoapods/l/TheKeyOAuthSwift.svg?style=flat)](https://cocoapods.org/pods/TheKeyOAuthSwift)
[![Platform](https://img.shields.io/cocoapods/p/TheKeyOAuthSwift.svg?style=flat)](https://cocoapods.org/pods/TheKeyOAuthSwift)

## Example

To run the example project, clone the repo, and run `pod install` from the Example directory first.

## Requirements

## Installation

TheKeyOAuthSwift is available through [CocoaPods](https://cocoapods.org). To install
it, simply add the following line to your Podfile:

```ruby
pod 'TheKeyOAuthSwift'
```

## Usage

#### Get a CAS Ticket

```swift
TheKeyOAuthClient.shared.performActionWithTicket(forService: "https://service.example.com/") { (result) in
  switch result {
  	case let .success(ticket):
  	  // do something with the ticket
  	case .failure(TheKeyOAuthClient.ApiError.notConfigured)
  	  // You should really configure the library before trying to use it
  	case let .failure(error):
  	  // handle the error as appropriate
  }
}
```

## Author

ryan.t.carlson@cru.org, ryan.t.carlson@cru.org

## License

TheKeyOAuthSwift is available under the MIT license. See the LICENSE file for more info.
