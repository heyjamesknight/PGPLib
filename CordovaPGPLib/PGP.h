//
//  NetPGP.h
//  PGP Demo
//
//  Created by James Knight on 6/9/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>


FOUNDATION_EXPORT NSString *const PGPOptionKeyType;
FOUNDATION_EXPORT NSString *const PGPOptionNumBits;
FOUNDATION_EXPORT NSString *const PGPOptionUserId;
FOUNDATION_EXPORT NSString *const PGPOptionUnlocked;

FOUNDATION_EXPORT NSString *const PGPPubringFilename;
FOUNDATION_EXPORT NSString *const PGPSecringFilename;

typedef NS_ENUM(NSUInteger, PGPMode) {
    PGPModeGenerate,
    PGPModeEncrypt,
    PGPModeDecrypt,
    PGPModeSign,
    PGPModeVerify
};


#pragma mark - PGP interface


@interface PGP : NSObject


#pragma mark Constructors

// Each constructor initializes netpgp properly for the required action:
+ (instancetype)keyGenerator;
+ (instancetype)decryptorWithPrivateKey:(NSString *)privateKey;
+ (instancetype)encryptor;
+ (instancetype)signerWithPrivateKey:(NSString *)privateKey;
+ (instancetype)verifier;


#pragma mark - Basic methods


- (void)generateKeysWithOptions:(NSDictionary *)options
                completionBlock:(void(^)(NSString *publicKey, NSString *privateKey))completionBlock
                     errorBlock:(void(^)(NSError *error))errorBlock;


- (void)decryptData:(NSData *)data
    completionBlock:(void(^)(NSData *decryptedData))completionBlock
         errorBlock:(void(^)(NSError *error))errorBlock;


- (void)encryptData:(NSData *)data
          publicKey:(NSString *)publicKey
    completionBlock:(void(^)(NSData *encryptedData))completionBlock
         errorBlock:(void(^)(NSError *error))errorBlock;


- (void)encryptData:(NSData *)data
         publicKeys:(NSArray *)publicKeys
    completionBlock:(void(^)(NSData *encryptedData))completionBlock
         errorBlock:(void(^)(NSError *error))errorBlock;


- (void)signData:(NSData *)data
 completionBlock:(void(^)(NSData *signedData))completionBlock
      errorBlock:(void(^)(NSError *error))errorBlock;


- (void)verifyData:(NSData *)data
        publicKeys:(NSArray *)publicKeys
   completionBlock:(void (^)(NSString *verifiedMessage, NSArray *verifiedKeyIds))completionBlock
        errorBlock:(void (^)(NSError *))errorBlock;

- (void)decryptAndVerifyData:(NSData *)data
                  publicKeys:(NSArray *)publicKeys
             completionBlock:(void (^)(NSString *decryptedMessage, NSArray *verifiedKeyIds))completionBlock
                  errorBlock:(void (^)(NSError *))errorBlock;


@end
