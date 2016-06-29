//
//  TouchID.m
//  Copyright (c) 2014 Lee Crossley - http://ilee.co.uk
//

#import "TouchID.h"

#import <LocalAuthentication/LocalAuthentication.h>

@implementation TouchID

- (void) authenticate:(CDVInvokedUrlCommand*)command;
{
    NSString *text = [command.arguments objectAtIndex:0];

    __block CDVPluginResult* pluginResult = nil;

    if (NSClassFromString(@"LAContext") != nil)
    {
        NSString *bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];
        SecAccessControlRef sacRef;
        CFErrorRef *err = nil;

        /*
         Important considerations.
         Please read the docs regarding kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly.
         TL;DR - If the user unsets their device passcode, these keychain items are destroyed.
         You will need to add code to compensate for this, i.e to say that touch ID can only be used if the device has a passcode set.

         Additionally, keychain entries with this flag will not be backed up/restored via iCloud.
         */

        //Gets our Security Access Controll ref for user presence policy (requires user AuthN)
        sacRef = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                 kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                 kSecAccessControlUserPresence,
                                                 err);

        NSDictionary *attributes = @{
                                     //Sec class, in this case just a password
                                     (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                     //Our service UUID/Name
                                     (__bridge id)kSecAttrService: bundleIdentifier,
                                     //The data to insert
                                     (__bridge id)kSecValueData: [@"SecurityViewAccount"
                                                                  dataUsingEncoding:NSUTF8StringEncoding],
                                     //Whether or not we want to prompt on insert
                                     (__bridge id)kSecUseNoAuthenticationUI: @YES,
                                     //Our security access control reference
                                     (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacRef
                                     };

        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            //Insert the data to the keychain, using our attributes dictionary
            OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, nil);

            /* Lets get our secret from the keychain.
             * User will be asked for Touch ID or device passcode if Touch ID not available
             * You could use LocalAuthentication's canEvaluatePolicy method to determine if this is a touch ID device first.
             */
            NSDictionary *query = @{
                                    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                    (__bridge id)kSecAttrService: bundleIdentifier,
                                    (__bridge id)kSecReturnData: @YES,
                                    (__bridge id)kSecUseOperationPrompt: text
                                    };

            dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                CFTypeRef dataTypeRef = NULL;

                OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
                if (status == errSecSuccess)
                {
                    NSData *resultData = ( __bridge_transfer NSData *)dataTypeRef;

                    NSString * result = [[NSString alloc]
                                         initWithData:resultData
                                         encoding:NSUTF8StringEncoding];


                    NSLog(@"Keychain entry: %@", result);
                    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];

                }
                else
                {
                    //log and return error
                    NSLog(@"Unable to save to keychain");
                    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Unable to save to keychain"];
                }
                [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
            });
        });

    }
    else
    {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

- (void) checkSupport:(CDVInvokedUrlCommand*)command;
{

    __block CDVPluginResult* pluginResult = nil;

    if (NSClassFromString(@"LAContext") != nil)
    {
        LAContext *laContext = [[LAContext alloc] init];
        NSError *authError = nil;

        if ([laContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&authError])
        {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        }
        else
        {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:[authError localizedDescription]];
        }
    }
    else
    {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
    }

    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

@end