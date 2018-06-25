//
//  TheKeyOAuthClient.swift
//  TheKeyOAuthSwift_Example
//
//  Created by Ryan Carlson on 6/25/18.
//  Copyright © 2018 CocoaPods. All rights reserved.
//

import Foundation
import GTMAppAuth

public class TheKeyOAuthClient {
    private(set) var clientID: String?
    private(set) var redirectURI: URL?
    private(set) var issuer: String?
    
    var baseCasURL: URL?
    
    private let loginPath = ["login"]
    private let tokenPath = ["oauth","token"]
    private let scopes = ["extended", "fullticket"]
    private var configuration: OIDServiceConfiguration?
    
    public static let shared = TheKeyOAuthClient()
    
    public func configure(baseCasURL: URL, clientID: String, redirectURI: URL, issuer: String) {
        self.baseCasURL = baseCasURL
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.issuer = issuer
        
        configuration = OIDServiceConfiguration(
            authorizationEndpoint: baseCasURL.appendingPathComponent(loginPath.joined(separator: "/")),
            tokenEndpoint: baseCasURL.appendingPathComponent(tokenPath.joined(separator: "/"))
        )
    }
    
    public func isConfigured() -> Bool {
        return configuration != nil && baseCasURL != nil && clientID != nil && redirectURI != nil && issuer != nil
    }
    
     public func doAuthorization(requestingViewController: UIViewController, currentDateTime: Date) -> OIDAuthorizationFlowSession? {
        guard isConfigured(),
            let clientID = clientID,
            let redirectURI = redirectURI,
            let configuration = configuration else { return nil }
        
        let request = OIDAuthorizationRequest(configuration: configuration,
                                              clientId: clientID,
                                              clientSecret: "", //TODO: get this value
                                              scopes: scopes,
                                              redirectURL: redirectURI,
                                              responseType: OIDResponseTypeCode,
                                              additionalParameters: nil)
        
        let authSession = OIDAuthState.authState(byPresenting: request, presenting: requestingViewController) { authState, error in
            guard let authState = authState, authState.isAuthorized == true else { return }
            
            guard let _ = authState.lastTokenResponse?.accessToken else { return /*no token*/ }
            guard let accessTokenExpirationDate = authState.lastTokenResponse?.accessTokenExpirationDate,
                accessTokenExpirationDate.compare(currentDateTime) == ComparisonResult.orderedDescending else { return /*expired token*/}
                        
            let authorization = GTMAppAuthFetcherAuthorization(authState: authState)
            
            GTMAppAuthFetcherAuthorization.save(authorization, toKeychainForName: "org.cru.\(self.issuer!)")
        }
        
        return authSession
    }
}
