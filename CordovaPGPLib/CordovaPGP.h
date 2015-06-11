//
//  CordovaPGP.h
//  PGP Demo
//
//  Created by James Knight on 6/10/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Cordova/CDV.h>


#pragma mark - CordovaPGP interface


@interface CordovaPGP : CDVPlugin


#pragma mark Methods


- (void)generateKeyPair:(CDVInvokedUrlCommand *)command;
- (void)signAndEncryptMessage:(CDVInvokedUrlCommand *)command;
- (void)decryptAndVerifyMessage:(CDVInvokedUrlCommand *)command;


@end
