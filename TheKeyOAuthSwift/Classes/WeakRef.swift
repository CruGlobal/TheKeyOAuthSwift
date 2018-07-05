//
//  WeakRef.swift
//  TheKeyOAuthSwift_Example
//
//  Created by Ryan Carlson on 7/5/18.
//  Copyright © 2018 CocoaPods. All rights reserved.
//

import Foundation

class WeakRef<T> where T: AnyObject {
    private(set) weak var value: T?
    
    init(value: T?) {
        self.value = value
    }
}
