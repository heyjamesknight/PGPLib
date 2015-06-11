//
//  PGPTestCase.m
//  CordovaPGPLib
//
//  Created by James Knight on 6/11/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#import "PGP.h"

@interface PGPTestCase : XCTestCase

- (void)testKeyGeneration;
- (void)testEncryptAndDecrypt;
- (void)testSignAndVerify;
- (void)testMultipleEncryption;

- (void)testEncryptAndDecryptWithPublicKey:(NSString *)publicKey privateKey:(NSString *)privateKey;
- (void)testSignAndVerifyWithPublicKey:(NSString *)publicKey privateKey:(NSString *)privateKey;

@end


@implementation PGPTestCase


- (void)setUp {
    [super setUp];
}


- (void)tearDown {
    [super tearDown];
}


- (void)testKeyGeneration {
    NSDictionary *options = @{@"keyType": @1,
                              @"numBits": @1024,
                              @"userId": @"James Knight <james@jknight.co>",
                              @"unlocked": @NO};
    
    PGP *keyGenerator = [PGP keyGenerator];
    [keyGenerator generateKeysWithOptions:options completionBlock:^(NSString *publicKey, NSString *privateKey) {
        // Print result:
        XCTAssertNotNil(publicKey, @"Public key is nil.");
        XCTAssertNotNil(privateKey, @"Private key is nil.");
        
        [self testEncryptAndDecryptWithPublicKey:publicKey privateKey:privateKey];
        [self testSignAndVerifyWithPublicKey:publicKey privateKey:privateKey];
        
        
    } errorBlock:^(NSError *error) {
        XCTFail(@"Failed generating key: %@", error);
    }];
}


- (void)testEncryptAndDecrypt {
    NSString *testPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"suzy" ofType:@"gpg"];
    NSString *testSecretPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"suzysecret" ofType:@"gpg"];
    NSString *testPublic = [NSString stringWithContentsOfFile:testPath encoding:NSUTF8StringEncoding error:nil];
    NSString *testPrivate = [NSString stringWithContentsOfFile:testSecretPath encoding:NSUTF8StringEncoding error:nil];
    
    [self testEncryptAndDecryptWithPublicKey:testPublic privateKey:testPrivate];
}


- (void)testSignAndVerify {
    NSString *testPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"suzy" ofType:@"gpg"];
    NSString *testSecretPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"suzysecret" ofType:@"gpg"];
    NSString *testPublic = [NSString stringWithContentsOfFile:testPath encoding:NSUTF8StringEncoding error:nil];
    NSString *testPrivate = [NSString stringWithContentsOfFile:testSecretPath encoding:NSUTF8StringEncoding error:nil];
    
    [self testSignAndVerifyWithPublicKey:testPublic privateKey:testPrivate];
}


- (void)testMultipleEncryption {
    // Load keys:
    NSString *suzyPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"suzy" ofType:@"gpg"];
    NSString *suzySecretPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"suzysecret" ofType:@"gpg"];
    NSString *suzyPublic = [NSString stringWithContentsOfFile:suzyPath encoding:NSUTF8StringEncoding error:nil];
    NSString *suzyPrivate = [NSString stringWithContentsOfFile:suzySecretPath encoding:NSUTF8StringEncoding error:nil];
    
    NSString *bobPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"bob" ofType:@"gpg"];
    NSString *bobSecretPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"bobsecret" ofType:@"gpg"];
    NSString *bobPublic = [NSString stringWithContentsOfFile:bobPath encoding:NSUTF8StringEncoding error:nil];
    NSString *bobPrivate = [NSString stringWithContentsOfFile:bobSecretPath encoding:NSUTF8StringEncoding error:nil];
    
    NSString *steveSecretPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"stevesecret" ofType:@"gpg"];
    NSString *stevePrivate = [NSString stringWithContentsOfFile:steveSecretPath encoding:NSUTF8StringEncoding error:nil];
    
    NSString *testMessage = @"Testing multiple recipient encryption.";
    
    // Encrypt the data:
    PGP *encyptor = [PGP encryptor];
    [encyptor encryptData:[testMessage dataUsingEncoding:NSUTF8StringEncoding]
               publicKeys:@[suzyPublic, bobPublic]
          completionBlock:^(NSData *result) {
              
              // Decrypt the result:
              
              PGP *suzyDecryptor = [PGP decryptorWithPrivateKey:suzyPrivate];
              PGP *bobDecryptor = [PGP decryptorWithPrivateKey:bobPrivate];
              PGP *steveDecryptor = [PGP decryptorWithPrivateKey:stevePrivate];
              
              [suzyDecryptor decryptData:result completionBlock:^(NSData *result) {
                  // Check that the result is the same as the input:
                  NSString *decryptedMessage = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
                  XCTAssertEqualObjects(testMessage, decryptedMessage, @"Source and result are not equal:\nSource: %@\nResult: %@", testMessage, decryptedMessage);
                  
              } errorBlock:^(NSError *error) {
                  XCTFail(@"Failed decrypting Suzy: %@", error);
              }];
              
              [bobDecryptor decryptData:result completionBlock:^(NSData *result) {
                  // Check that the result is the same as the input:
                  NSString *decryptedMessage = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
                  XCTAssertEqualObjects(testMessage, decryptedMessage, @"Source and result are not equal:\nSource: %@\nResult: %@", testMessage, decryptedMessage);
                  
              } errorBlock:^(NSError *error) {
                  XCTFail(@"Failed decrypting Bob: %@", error);
              }];
              
              [steveDecryptor decryptData:result completionBlock:^(NSData *result) {
                  // Steve should fail, as he wasn't in the encryption list:
                  XCTFail(@"Steve successfully decrypted a message not intended for him!");
                  
              } errorBlock:^(NSError *error) {
                  // This is actually the success case.
              }];
              
          } errorBlock:^(NSError *error) {
              XCTFail(@"Failed encrypting: %@", error);
          }];
}


- (void)testSignAndVerifyWithPublicKey:(NSString *)publicKey privateKey:(NSString *)privateKey {
    NSString *testMessage = @"Testing signing/verifying.";
    
    PGP *signer = [PGP signerWithPrivateKey:privateKey];
    [signer signData:[testMessage dataUsingEncoding:NSUTF8StringEncoding] completionBlock:^(NSData *result) {
        
        PGP *verifier = [PGP verifier];
        [verifier verifyData:result publicKeys:@[publicKey] completionBlock:^(NSData *verifiedData, NSArray *verifiedKeys) {
            
            XCTAssertNotNil(verifiedData, @"verifiedData is nil.");
            XCTAssertNotNil(verifiedKeys, @"verifiedKeys is nil.");
            XCTAssertEqual(verifiedKeys.count, 1, @"Verify failed, failed to return verified keys.");
            
        } errorBlock:^(NSError *error) {
            XCTFail(@"Failed validating: %@", error);
        }];
    } errorBlock:^(NSError *error) {
        XCTFail(@"Failed signing: %@", error);
    }];
}


- (void)testEncryptAndDecryptWithPublicKey:(NSString *)publicKey privateKey:(NSString *)privateKey {
    
    NSString *testMessage = @"Testing encryption/decryption.";
    
    // Encrypt the test message using the new key:
    PGP *encryptor = [PGP encryptor];
    [encryptor encryptData:[testMessage dataUsingEncoding:NSUTF8StringEncoding]
                 publicKey:publicKey
           completionBlock:^(NSData *result) {
               PGP *decryptor = [PGP decryptorWithPrivateKey:privateKey];
               
               // Decrypt the result:
               [decryptor decryptData:result
                      completionBlock:^(NSData *result) {
                          
                          NSString *decryptedMessage = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
                          XCTAssertEqualObjects(testMessage, decryptedMessage, @"Source and result are not equal:\nSource: %@\nResult: %@", testMessage, decryptedMessage);
                          
                      } errorBlock:^(NSError *error) {
                          XCTFail(@"Failed decrypting: %@", error);
                      }];
               
           } errorBlock:^(NSError *error) {
               XCTFail(@"Failed encrypting: %@", error);
           }];
}

@end
