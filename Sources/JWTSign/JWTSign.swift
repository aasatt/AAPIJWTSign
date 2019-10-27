import SwiftJWT
import Foundation

public enum ExpTime {
    case twentyMinutes, sixMonths
    
    var seconds: TimeInterval {
        switch self {
        case .twentyMinutes:
            return 1200
        case .sixMonths:
            return 15777000
        }
    }
}

struct ASCClaims: Claims {
    
    let iss: String
    let exp: Int
    let aud = "appstoreconnect-v1"
    
    init(issuer: String, expiration: ExpTime) {
        iss = issuer
        exp = Int(floor(Date().addingTimeInterval(expiration.seconds).timeIntervalSince1970))
    }
}

struct AMClaims: Claims {
    
    let iss: String
    let exp: Int
    let iat: Date
    
    init(issuer: String, expiration: ExpTime) {
        iss = issuer
        iat = Date()
        exp = Int(floor(Date().addingTimeInterval(expiration.seconds).timeIntervalSince1970))
    }
}

struct APNSClaims: Claims {
    
    let iss: String
    let iat: Date
    
    init(issuer: String) {
        iss = issuer
        iat = Date()
    }
    
}


public class JWTSign {
    
    public static func getJWTTokenForASC(key: Data, keyId: String, issuer: String) -> String? {
        let header = Header(typ: "JWT", kid: keyId)
        let claims = ASCClaims(issuer: issuer, expiration: .twentyMinutes)
        var jwt = JWT(header: header, claims: claims)
        let signer = JWTSigner.es256(privateKey: key)
        do {
            return try jwt.sign(using: signer)
        } catch {
            print(error)
        }
        return nil
    }
    
    public static func getJWTTokenForAM(key: Data, keyId: String, issuer: String) -> String? {
        let header = Header(typ: "JWT", kid: keyId)
        let claims = AMClaims(issuer: issuer, expiration: .sixMonths)
        var jwt = JWT(header: header, claims: claims)
        let signer = JWTSigner.es256(privateKey: key)
        do {
            return try jwt.sign(using: signer)
        } catch {
            print(error)
        }
        return nil
    }
    
    public static func getJWTTokenForAPNS(key: Data, keyId: String, issuer: String) -> String? {
        let header = Header(kid: keyId)
        let claims = APNSClaims(issuer: issuer)
        var jwt = JWT(header: header, claims: claims)
        let signer = JWTSigner.es256(privateKey: key)
        do {
            return try jwt.sign(using: signer)
        } catch {
            print(error)
        }
        return nil
    }
    
}
