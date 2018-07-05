//
//  TheKeyOAuthClient.swift
//  TheKeyOAuthSwift_Example
//
//  Created by Ryan Carlson on 6/25/18.
//  Copyright © 2018 CocoaPods. All rights reserved.
//

import Foundation
import GTMAppAuth
import Result

public class TheKeyOAuthClient: NSObject {
    // MARK: Constants

    private static let kDefaultBaseURL = URL(string: "https://thekey.me/cas/")
    
    private static let kTokenPath = "api/oauth/token"
    private static let kLoginPath = "login"
    
    private static let kbundleUnknown = "org.cru.unknownApp"
    private static let kKeychainName = "%@.thekey.authorization"
    
    private static let kParamTicket = "ticket"

    private static let kGUIDKey = "ssoGuid"
    private static let kEmailKey = "email"
    private static let kgrMasterPersonIdKey = "grMasterPersonId"
    
    // MARK: Private variables
    
    private var clientID: String?
    private var redirectURI: URL?
    private var baseCasURL: URL?

    private let scopes = ["extended", "fullticket"]

    private var keychainName: String {
        get {
            let identifier = Bundle.main.bundleIdentifier ?? TheKeyOAuthClient.kbundleUnknown
            let keychainName = String(format: TheKeyOAuthClient.kKeychainName, identifier)
            return keychainName
        }
    }
    
    private var userAttrs: [String: String]?
    
    private var authState: OIDAuthState?
    private var configuration: OIDServiceConfiguration?

    fileprivate var stateChangeDelegates = [WeakRef<OIDAuthStateChangeDelegate>]()

    // MARK: Errors we can throw/return

    public enum ApiError: Error {
        case notConfigured
        case missingAccessToken
        case unableToBuildURL
        case invalidApiResponse
    }

    // MARK: Static singleton instance
    
    public static let shared = TheKeyOAuthClient()
    
    // MARK: Public variables
    
    public var userAttributes: [String: String]? {
        get {
            guard isConfigured(), isAuthenticated() else { userAttrs = nil; return nil }
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
    public func configure(baseCasURL: URL?, clientID: String, redirectURI: URL) {
        self.baseCasURL = baseCasURL ?? TheKeyOAuthClient.kDefaultBaseURL
        self.clientID = clientID
        self.redirectURI = redirectURI

        let authorizationEndpoint = baseCasURL!.appendingPathComponent(TheKeyOAuthClient.kLoginPath)
        let tokenEndpoint = baseCasURL!.appendingPathComponent(TheKeyOAuthClient.kTokenPath)
        
        configuration = OIDServiceConfiguration(
            authorizationEndpoint: authorizationEndpoint,
            tokenEndpoint: tokenEndpoint
        )
        loadAuthStateFromKeychain()
    }
    /* Returns true if the client is configured with the values necessary interact with TheKey.
       It is a safe assumption that if configure() is called then this function will return true. */
    public func isConfigured() -> Bool {
        return configuration != nil && baseCasURL != nil && clientID != nil && redirectURI != nil
    }
    
    /* Returns true if there is a valid authState, which may be loaded from the Keychain. */
    public func isAuthenticated() -> Bool {
        return authState?.isAuthorized ?? false
    }
    
    /* This function initiates an authorization flow by presenting a SFSafariViewController returning an Authorization Session
       that the caller should set in the AppDelegate to handle the redirect that will be sent after a successful authorization.
       If authorization is successful, then the client will persist the authorization to the keychain and fetch attributes for the user
       and store them in userAttrs. */
    public func initiateAuthorization(requestingViewController: UIViewController, additionalParameters: [String: String]? = nil,
                                      callback: ((Error) -> Void)? = nil) -> OIDAuthorizationFlowSession? {
        guard isConfigured(), let clientID = clientID, let redirectURI = redirectURI, let configuration = configuration else { return nil }
        
        let request = OIDAuthorizationRequest(configuration: configuration,
                                              clientId: clientID,
                                              clientSecret: nil,
                                              scopes: scopes,
                                              redirectURL: redirectURI,
                                              responseType: OIDResponseTypeCode,
                                              additionalParameters: additionalParameters)
        
        let authSession = OIDAuthState.authState(byPresenting: request, presenting: requestingViewController) { authState, error in
            if let error = error {
                callback?(error)
                return
            }
            
            guard let authState = authState else { return }
            
            self.authState = authState
            self.updateStoredAuthState()
            self.authState?.stateChangeDelegate = self
            self.fetchAttributes()
        }
        
        return authSession
    }

    /* Nukes the user attributes, authState and removes authState from the keychain */
    public func logout() {
        userAttrs = nil
        authState = nil
        self.updateStoredAuthState()
    }
    
    /* Fetches attributes for the logged in user. The user MUST have a valid, non-expired session. The function DOES account
       for refresh tokens. Retrieved attributes will be stored in userAttrs and a copy is returned in the result callback. */
    public func fetchAttributes(result: (([String: String]?, Error?) -> Void)? = nil) {
        guard isConfigured(), let authState = authState else { return }
        
        authState.performAction { (token, _, error) in
            if error != nil { result?(nil, error); return }
            guard let token = token else { return }
            guard let request = self.buildAttributesRequest(with: token) else { return }
            
            let session = URLSession(configuration: .ephemeral)
            
            let task = session.dataTask(with: request) { (data, response, error) in
                if let data = data {
                    guard let json = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: String] else { return }
                    self.userAttrs = json
                    result?(json, nil)
                }
            }
            
            task.resume()
        }
    }

    public func performActionWithTicket(forService service: String, completion: ((Result<String, AnyError>) -> Void)?)  {
        guard isConfigured(), let authState = authState else { completion?(.failure(AnyError(ApiError.notConfigured))); return }

        authState.performAction { (token, _, error) in
            if let error = error { completion?(.failure(AnyError(error))); return }

            guard let token = token else { completion?(.failure(AnyError(ApiError.missingAccessToken))); return }
            guard let request = self.buildTicketRequest(with: token, forService: service) else { completion?(.failure(AnyError(ApiError.unableToBuildURL))); return }

            let session = URLSession(configuration: .ephemeral)
            let task = session.dataTask(with: request) { (data, response, error) in
                if let error = error { completion?(.failure(AnyError(error))); return }

                do {
                    if let data = data {
                        let json = try JSONSerialization.jsonObject(with: data) as? [String: String]
                        completion?(Result(json?[TheKeyOAuthClient.kParamTicket], failWith: AnyError(ApiError.invalidApiResponse)))
                        return
                    }
                } catch {
                    completion?(.failure(AnyError(error)))
                    return
                }

                completion?(.failure(AnyError(ApiError.invalidApiResponse)))
                return
            }

            task.resume()
        }
    }

    // MARK: Helper functions

    func buildCasURL(with path: String) -> URL? {
        guard let baseCasURL = self.baseCasURL else { return nil }
        return baseCasURL.appendingPathComponent(path)
    }

    private func loadAuthStateFromKeychain() {
        guard let authorization = GTMAppAuthFetcherAuthorization.init(fromKeychainForName: keychainName) else { return }
        authState = authorization.authState
        authState?.stateChangeDelegate = self
    }

    private func updateStoredAuthState() {
        if let authState = authState, authState.isAuthorized {
            let authorization = GTMAppAuthFetcherAuthorization(authState: authState)
            GTMAppAuthFetcherAuthorization.save(authorization, toKeychainForName: self.keychainName)
        } else {
            GTMAppAuthFetcherAuthorization.removeFromKeychain(forName: keychainName)
            self.authState = nil
            self.userAttrs = nil
        }
    }
}

//MARK: OIDAuthState Delegate
extension TheKeyOAuthClient: OIDAuthStateChangeDelegate {
    public func didChange(_ state: OIDAuthState) {
        updateStoredAuthState()

        compactDelegates()
        for delegate in stateChangeDelegates {
            delegate.value?.didChange(state)
        }
    }

    public func addStateChangeDelegate(delegate: OIDAuthStateChangeDelegate) {
        stateChangeDelegates.append(WeakRef(value: delegate))
        compactDelegates()
    }

    private func compactDelegates() {
        stateChangeDelegates = stateChangeDelegates.filter { $0.value != nil }
    }
}

private extension TheKeyOAuthClient {
    private static let kAttributesPath = "api/oauth/attributes"
    private static let kTicketPath = "api/oauth/ticket"
    
    private static let kAuthorizationHeaderKey = "Authorization"
    private static let kAuthorizationHeaderValue = "Bearer %@"
    
    private static let kParamService = "service"
    
    func buildAttributesRequest(with token: String) -> URLRequest? {
        guard let attributesURL = buildCasURL(with: TheKeyOAuthClient.kAttributesPath) else { return nil }
        
        var request = URLRequest(url: attributesURL)
        let bearerToken = String(format:TheKeyOAuthClient.kAuthorizationHeaderValue, token)
        
        request.setValue(bearerToken, forHTTPHeaderField: TheKeyOAuthClient.kAuthorizationHeaderKey)
        
        return request
    }
    
    func buildTicketRequest(with token: String, forService service: String) -> URLRequest? {
        guard let rawTicketURL = buildCasURL(with: TheKeyOAuthClient.kTicketPath) else { return nil }
        guard var ticketURL = URLComponents(url: rawTicketURL, resolvingAgainstBaseURL: false) else { return nil }
        let serviceParam = URLQueryItem(name: TheKeyOAuthClient.kParamService, value: service)
        ticketURL.queryItems = [serviceParam]
        guard let urlWIthParams = ticketURL.url else { return nil }
        
        var request = URLRequest(url: urlWIthParams)
        let bearerToken = String(format: TheKeyOAuthClient.kAuthorizationHeaderValue, token)
        
        request.setValue(bearerToken, forHTTPHeaderField: TheKeyOAuthClient.kAuthorizationHeaderKey)
        
        return request
    }
}
