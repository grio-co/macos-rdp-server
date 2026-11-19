#import "daemon/UpdateVerify.h"
#import <Foundation/Foundation.h>
#import <Security/Security.h>

bool update_verify_signature(const char *path, const char **why) {
    const char *reason = NULL;
    SecStaticCodeRef code = NULL;
    SecRequirementRef req = NULL;
    CFDictionaryRef info = NULL;
    @autoreleasepool {
        NSURL *url = path ? [NSURL fileURLWithPath:@(path)] : nil;
        if (!url || SecStaticCodeCreateWithPath((__bridge CFURLRef)url, kSecCSDefaultFlags,
                                                &code) != errSecSuccess || !code) {
            reason = "cannot open the file as code";
        } else if (SecRequirementCreateWithString(CFSTR(UPDATE_REQUIREMENT), kSecCSDefaultFlags,
                                                  &req) != errSecSuccess || !req) {
            reason = "requirement text does not parse";
        } else {
            OSStatus st = SecStaticCodeCheckValidity(
                code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, req);
            if (st == errSecCSUnsigned)             reason = "unsigned";
            else if (st == errSecCSSignatureFailed) reason = "signature invalid or contents modified";
            else if (st == errSecCSReqFailed)
                reason = "not a Developer ID signature from team FQKL8883DP for com.macosrdp.daemon";
            else if (st != errSecSuccess)           reason = "signature validation failed";
            else if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info)
                         != errSecSuccess || !info)
                reason = "cannot read signing information";
            else {
                NSNumber *flags = ((__bridge NSDictionary *)info)[(__bridge NSString *)kSecCodeInfoFlags];
                if (!(flags.unsignedIntValue & kSecCodeSignatureRuntime))
                    reason = "hardened runtime not enabled";
            }
        }
    }
    if (info) CFRelease(info);
    if (req)  CFRelease(req);
    if (code) CFRelease(code);
    if (why) *why = reason;
    return reason == NULL;
}
