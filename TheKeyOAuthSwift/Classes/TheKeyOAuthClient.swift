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
    // MARK: Constants
    
    private static let kAuthorizationHeaderKey = "Authorization"
    private static let kAuthorizationHeaderValue = "Bearer %@"
    private static let kIssuerUnknown = "unknownApp"
    private static let kKeychainName = "org.cru.%@.authorization"
    private static let kGUIDKey = "ssoGuid"
    private static let kEmailKey = "email"
    private static let kgrMasterPersonIdKey = "grMasterPersonId"
    
    // MARK: Private variables
    
    private var clientID: String?
    private var redirectURI: URL?
    private var issuer: String?
    private var baseCasURL: URL?

    private let scopes = ["extended", "fullticket"]

    private let loginPath = ["login"]
    private let tokenPath = ["api","oauth","token"]
    private let attributesPath = ["api","oauth","attributes"]
    
    private var keychainName: String {
        get {
            let issuer = self.issuer ?? TheKeyOAuthClient.kIssuerUnknown
            let keychainName = String(format: TheKeyOAuthClient.kKeychainName, issuer)
            return keychainName
        }
    }
    
    private var userAttrs: [String: String]?
    
    private var authState: OIDAuthState?
    private var configuration: OIDServiceConfiguration?

    // MARK: Static singleton instance
    
    public static let shared = TheKeyOAuthClient()
    
    // MARK: Public variables
    
    public var userAttributes: [String: String]? {
        get {
            guard isConfigured(), isAuthenticated(at: Date()) else { userAttrs = nil; return nil }
            return userAttrs
        }
    }
    
    public var guid: String? {
        get {
            return userAttributes?[TheKeyOAuthClient.kGUIDKey]
        }
    }
    
    public var email: String? {
        get {
            return userAttributes?[TheKeyOAuthClient.kEmailKey]
        }
    }
    
    public var grMasterPersonId: String? {
        get {
            return userAttributes?[TheKeyOAuthClient.kgrMasterPersonIdKey]
        }
    }
    
    // MARK: Public functions
    
    /* Configures the client with values necessary to interact with TheKey. This function MUST
       be called before any subsequent calls should be expected to work. */
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
    /* Returns true if the client is configured with the values necessary interact with TheKey.
       It is a safe assumption that if configure() is called then this function will return true. */
    public func isConfigured() -> Bool {
        return configuration != nil && baseCasURL != nil && clientID != nil && redirectURI != nil && issuer != nil
    }
    
    /* Returns true if there is a valid authState, which may be loaded from the Keychain, and that authState has an
       access token that has not expired. This function DOES NOT take refresh tokens into account. */
    public func isAuthenticated(at currentDateTime: Date = Date()) -> Bool {
        if authState == nil {
            loadAuthStateFromKeychain()
        }
        guard let accessTokenExpirationDate = authState?.lastTokenResponse?.accessTokenExpirationDate else { return false }
        return accessTokenExpirationDate.compare(currentDateTime) == ComparisonResult.orderedDescending
    }
    
    /* This function initiates an authorization flow by presenting a SFSafariViewController returning an Authorization Session
       that the caller should set in the AppDelegate to handle the redirect that will be sent after a successful authorization.
       If authorization is successful, then the client will persist the authorization to the keychain and fetch attributes for the user
       and store them in userAttrs. */
    public func initiateAuthorization(requestingViewController: UIViewController,
                                      currentDateTime: Date,
                                      callback: @escaping (Error) -> Void) -> OIDAuthorizationFlowSession? {
        guard isConfigured(), let clientID = clientID, let redirectURI = redirectURI, let configuration = configuration else { return nil }
        
        let request = OIDAuthorizationRequest(configuration: configuration,
                                              clientId: clientID,
                                              clientSecret: nil,
                                              scopes: scopes,
                                              redirectURL: redirectURI,
                                              responseType: OIDResponseTypeCode,
                                              additionalParameters: nil)
        
        let authSession = OIDAuthState.authState(byPresenting: request, presenting: requestingViewController) { authState, error in
            if let error = error {
                callback(error)
                return
            }
            
            guard let authState = authState, self.isAuthenticated(at: currentDateTime) else { return }
            
            self.saveToKeychain(authState: authState)
            self.fetchAttributes()
        }
        
        return authSession
    }
    
    /* Nukes the user attributes, authState and removes authState from the keychain */
    public func logout() {
        userAttrs = nil
        authState = nil
        GTMAppAuthFetcherAuthorization.removeFromKeychain(forName: keychainName)
    }
    
    /* Fetches attributes for the logged in user. The user MUST have a valid, non-expired session. The function DOES account
       for refresh tokens. Retrieved attributes will be stored in userAttrs and a copy is returned in the result callback. */
    public func fetchAttributes(result: (([String: String]?, Error?) -> Void)?) {
        guard isConfigured(), let authState = authState, let baseURL = baseCasURL else { return }
        
        authState.performAction { (token, _, _) in
            guard let token = token else { return }
            guard let request = self.buildAttributesRequest(with: token) else { return }
            
            let session = URLSession(configuration: .ephemeral)
            
            let task = session.dataTask(with: request) { (data, response, error) in
                if let data = data {
                    do {
                        guard let json = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: String] else { return }
                        self.userAttrs = json
                        result?(json, nil)
                    } catch { result?(nil, error)}
                }
            }
            
            task.resume()
        }
    }
    
    // MARK: Helper functions

    private func buildAttributesRequest(with token: String) -> URLRequest? {
        guard let baseCasURL = baseCasURL else { return nil }
        
        let attributesURL = baseCasURL.appendingPathComponent(attributesPath.joined(separator: "/"))
        var request = URLRequest(url: attributesURL)
        let bearerToken = String(format:TheKeyOAuthClient.kAuthorizationHeaderValue, token)
        
        request.setValue(bearerToken, forHTTPHeaderField: TheKeyOAuthClient.kAuthorizationHeaderKey)
        
        return request
    }
    
    private func saveToKeychain(authState: OIDAuthState) {
        let authorization = GTMAppAuthFetcherAuthorization(authState: authState)
        
        GTMAppAuthFetcherAuthorization.save(authorization, toKeychainForName: self.keychainName)
    }
    
    private func loadAuthStateFromKeychain() {
        guard let authorization = GTMAppAuthFetcherAuthorization.init(fromKeychainForName: keychainName) else { return }
        authState = authorization.authState
    }
    
    private func fetchAttributes() {
        fetchAttributes(result: nil)
    }
}
