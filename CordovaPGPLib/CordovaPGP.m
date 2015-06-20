//
//  CordovaPGP.m
//  PGP Demo
//
//  Created by James Knight on 6/11/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "CordovaPGP.h"
#import "PGP.h"

typedef void (^CordovaPGPErrorBlock)(NSError *);


#pragma mark - CordovaPGP extension


@interface CordovaPGP ()

- (void(^)(NSError *))createErrorBlockForCommand:(CDVInvokedUrlCommand *)command;

@end


#pragma mark - CordovaPGP implementation


@implementation CordovaPGP


#pragma mark Methods


- (void)generateKeyPair:(CDVInvokedUrlCommand *)command {
    
    // Define error callback:
    CordovaPGPErrorBlock errorBlock = [self createErrorBlockForCommand:command];
    
    // Perform command:
    [self.commandDelegate runInBackground:^{
        NSDictionary *options = [command.arguments objectAtIndex:0];
        
        PGP *generator = [PGP keyGenerator];
        [generator generateKeysWithOptions:options completionBlock:^(NSString *publicKey, NSString *privateKey) {
            
            NSDictionary *keys = @{@"privateKeyArmored": privateKey,
                                   @"publicKeyArmored": publicKey};
            
            CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                          messageAsDictionary:keys];
            
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
            
        } errorBlock:errorBlock];
    }];
}


- (void)signAndEncryptMessage:(CDVInvokedUrlCommand *)command {
    
    // Define error callback:
    CordovaPGPErrorBlock errorBlock = [self createErrorBlockForCommand:command];
    
    // Perform command:
    [self.commandDelegate runInBackground:^{
        
        // Get the arguments from the command:
        NSArray *publicKeys = [command.arguments objectAtIndex:0];
        NSString *privateKey = [command.arguments objectAtIndex:1];
        NSString *text = [command.arguments objectAtIndex:2];
        
        // Sign the text first:
        PGP *signer = [PGP signerWithPrivateKey:privateKey];
        [signer signData:[text dataUsingEncoding:NSUTF8StringEncoding] completionBlock:^(NSData *signedData) {
            
            // Signing was successful, now encrypt the text:
            PGP *encryptor = [PGP encryptor];
            
            [encryptor encryptData:signedData publicKeys:publicKeys completionBlock:^(NSData *encryptedData) {
                
                NSString *result = [[NSString alloc] initWithData:encryptedData encoding:NSUTF8StringEncoding];
                
                CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                                  messageAsString:result];
                
                [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                
            } errorBlock:errorBlock];
            
        } errorBlock:errorBlock];
    }];
}


- (void)decryptAndVerifyMessage:(CDVInvokedUrlCommand *)command {
    
    // Define error callback:
    CordovaPGPErrorBlock errorBlock = [self createErrorBlockForCommand:command];
    
    // Perform command:
    [self.commandDelegate runInBackground:^{
        
        // Get the arguments from the command:
        NSString *privateKey = [command.arguments objectAtIndex:0];
        NSArray *publicKeys = [command.arguments objectAtIndex:1];
        NSString *msg = [command.arguments objectAtIndex:2];
        
        // Decrypt the data:
        PGP *decryptor = [PGP decryptorWithPrivateKey:privateKey];

        [decryptor decryptAndVerifyData:[msg dataUsingEncoding:NSUTF8StringEncoding] publicKeys:publicKeys completionBlock:^(NSString *decryptedMessage, NSArray *verifiedKeyIds) {
            
            NSMutableArray *verifiedSignatures = [NSMutableArray array];
            
            for (NSString *keyId in verifiedKeyIds) {
                [verifiedSignatures addObject:@{@"keyid": keyId, @"valid": @YES}];
            }
            
            NSDictionary *result = @{@"text": decryptedMessage, @"signatures": [NSArray arrayWithArray:verifiedSignatures]};
            
            CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                          messageAsDictionary:result];
            
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        
        } errorBlock:errorBlock];
    }];
}


#pragma mark Private methods


- (void(^)(NSError *error))createErrorBlockForCommand:(CDVInvokedUrlCommand *)command {
    return ^(NSError *error) {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                          messageAsString:error.description];
        
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    };
}

@end
