#import "TouchID.h"
#import <React/RCTUtils.h>
#import "React/RCTConvert.h"

@implementation TouchID

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(isSupported: (RCTResponseSenderBlock)callback)
{
    LAContext *context = [[LAContext alloc] init];
    NSError *error;

    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
        callback(@[[NSNull null], [self getBiometryType:context]]);
        // Device does not support TouchID
    } else {
        callback(@[RCTMakeError(@"RCTTouchIDNotSupported", nil, nil)]);
        return;
    }
}

RCT_EXPORT_METHOD(authenticate: (NSString *)reason
                  options:(NSDictionary *)options
                  callback: (RCTResponseSenderBlock)callback)
{
    LAContext *context = [[LAContext alloc] init];
    NSError *error;

    if (RCTNilIfNull([options objectForKey:@"fallbackLabel"]) != nil) {
        NSString *fallbackLabel = [RCTConvert NSString:options[@"fallbackLabel"]];   
        context.localizedFallbackTitle = fallbackLabel;
    }

    // Device has TouchID
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
        // Attempt Authentification
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                localizedReason:reason
                          reply:^(BOOL success, NSError *error)
         {
             if (success) { // Authentication Successful
                 callback(@[[NSNull null], @"Authenticated with Touch ID."]);
             } else if (error) { // Authentication Error
                 NSString *errorReason;

                 switch (error.code) {
                     case LAErrorAuthenticationFailed:
                         errorReason = @"LAErrorAuthenticationFailed";
                         break;

                     case LAErrorUserCancel:
                         errorReason = @"LAErrorUserCancel";
                         break;

                     case LAErrorUserFallback:
                         errorReason = @"LAErrorUserFallback";
                         break;

                     case LAErrorSystemCancel:
                         errorReason = @"LAErrorSystemCancel";
                         break;

                     case LAErrorPasscodeNotSet:
                         errorReason = @"LAErrorPasscodeNotSet";
                         break;

                     case LAErrorTouchIDNotAvailable:
                         errorReason = @"LAErrorTouchIDNotAvailable";
                         break;

                     case LAErrorTouchIDNotEnrolled:
                         errorReason = @"LAErrorTouchIDNotEnrolled";
                         break;

                     default:
                         errorReason = @"RCTTouchIDUnknownError";
                         break;
                 }

                 NSLog(@"Authentication failed: %@", errorReason);
                 callback(@[RCTMakeError(errorReason, nil, nil)]);
             } else { // Authentication Failure
                 callback(@[RCTMakeError(@"LAErrorAuthenticationFailed", nil, nil)]);
             }
         }];

        // Device does not support TouchID
    } else {
        callback(@[RCTMakeError(@"RCTTouchIDNotSupported", nil, nil)]);
        return;
    }
}

- (NSString *)getBiometryType:(LAContext *)context
{
    if (@available(iOS 11, *)) {
        return (context.biometryType == LABiometryTypeFaceID) ? @"FaceID" : @"TouchID";
    }

    return @"TouchID";
}

RCT_EXPORT_METHOD(isSupportedPasscode: (RCTResponseSenderBlock)callback)
{

    if (![self supportsPasscodeAuth]) {
        callback(@[RCTMakeError(@"PasscodeAuthNotSupported", nil, nil)]);
        return;
    }

    LAContext *context = [[LAContext alloc] init];

    // Check if PasscodeAuth Authentication is available
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:nil]) {
        callback(@[[NSNull null], @true]);
    // PasscodeAuth is not set
    } else {
        callback(@[RCTMakeError(@"PasscodeAuthNotSet", nil, nil)]);
        return;
    }

}
RCT_EXPORT_METHOD(authenticatePasscode: (NSString *)reason
                  callback: (RCTResponseSenderBlock)callback)
{
    if (![self supportsPasscodeAuth]) {
        callback(@[RCTMakeError(@"PasscodeAuthNotSupported", nil, nil)]);
        return;
    }

    LAContext *context = [[LAContext alloc] init];
    NSError *error;

    // Device has PasscodeAuth
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
        // Attempt Authentication
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                localizedReason:reason
                          reply:^(BOOL success, NSError *error)
         {
             // Failed Authentication
             if (error) {
                 NSString *errorReason;

                 switch (error.code) {
                     case LAErrorAuthenticationFailed:
                         errorReason = @"LAErrorAuthenticationFailed";
                         break;

                     case LAErrorUserCancel:
                         errorReason = @"LAErrorUserCancel";
                         break;

                     case LAErrorUserFallback:
                         errorReason = @"LAErrorUserFallback";
                         break;

                     case LAErrorSystemCancel:
                         errorReason = @"LAErrorSystemCancel";
                         break;

                     case LAErrorPasscodeNotSet:
                         errorReason = @"LAErrorPasscodeNotSet";
                         break;

                     default:
                         errorReason = @"PasscodeAuthUnknownError";
                         break;
                 }

                 NSLog(@"Authentication failed: %@", errorReason);
                 callback(@[RCTMakeError(errorReason, nil, nil)]);
                 return;
             }

             // Authenticated Successfully
             callback(@[[NSNull null], @"Authenticated with PasscodeAuth."]);
         }];

    // Device does not support PasscodeAuth
    } else {
        callback(@[RCTMakeError(@"PasscodeAuthNotSet", nil, nil)]);
        return;
    }
}
- (BOOL)supportsPasscodeAuth {
    // PasscodeAuth is only available in iOS 9.  In iOS8, `LAPolicyDeviceOwnerAuthentication` is present but not implemented.
    float osVersion = [[[UIDevice currentDevice] systemVersion] floatValue];

    return osVersion >= 9.0;
}

@end


