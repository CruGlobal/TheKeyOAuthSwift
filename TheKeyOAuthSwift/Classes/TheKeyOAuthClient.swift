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
    private let tokenPath = ["api","oauth","token"]
    private let scopes = ["extended", "fullticket"]
    private var configuration: OIDServiceConfiguration?
    
    public static let shared = TheKeyOAuthClient()
    
    public func configure(baseCasURL: URL, clientID: String, redirectURI: URL, issuer: String) {
        self.baseCasURL = baseCasURL
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.issuer = issuer
        
        let authorizationEndpoint: URL = baseCasURL.appendingPathComponent(loginPath.joined(separator: "/"))
        let tokenEndpoint: URL = baseCasURL.appendingPathComponent(tokenPath.joined(separator: "/"))
        
        configuration = OIDServiceConfiguration(
            authorizationEndpoint: authorizationEndpoint,
            tokenEndpoint: tokenEndpoint
        )
    }
    
    public func isConfigured() -> Bool {
        return configuration != nil && baseCasURL != nil && clientID != nil && redirectURI != nil && issuer != nil
    }
    
    public func isAuthenticated(at currentDateTime: Date = Date()) -> Bool {
        guard let auth = GTMAppAuthFetcherAuthorization(fromKeychainForName: keychainName()) else { return false }
        return isAuthorized(at: currentDateTime, authState: auth.authState)
    }
    
    public func doAuthorization(requestingViewController: UIViewController, currentDateTime: Date) -> OIDAuthorizationFlowSession? {
        guard isConfigured(),
            let clientID = clientID,
            let redirectURI = redirectURI,
            let configuration = configuration else { return nil }
        
        let request = OIDAuthorizationRequest(configuration: configuration,
                                              clientId: clientID,
                                              clientSecret: nil,
                                              scopes: scopes,
                                              redirectURL: redirectURI,
                                              responseType: OIDResponseTypeCode,
                                              additionalParameters: nil)
        
        let authSession = OIDAuthState.authState(byPresenting: request, presenting: requestingViewController) { authState, error in
            if let error = error {
                debugPrint(error)
                return
            }
            
            guard let authState = authState, authState.isAuthorized == true else { return }
            
            let authorization = GTMAppAuthFetcherAuthorization(authState: authState)
            
            GTMAppAuthFetcherAuthorization.save(authorization, toKeychainForName: self.keychainName())
            GTMAppAuthFetcherAuthorization.removeFromKeychain(forName: self.keychainName())
        }
        
        return authSession
    }
    
    private func isAuthorized(at currentDateTime: Date, authState: OIDAuthState) -> Bool {
        guard let accessTokenExpirationDate = authState.lastTokenResponse?.accessTokenExpirationDate else { return false }
        return accessTokenExpirationDate.compare(currentDateTime) == ComparisonResult.orderedDescending
    }
    
    private func keychainName() -> String {
        let issuer = self.issuer ?? "unknownApp"
        let keychainName = "org.cru.\(issuer).authorization"
        return keychainName
    }
}
