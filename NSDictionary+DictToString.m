//
//  NSDictionary+DictToString.m
//  iSH
//
//  Created by Brad Barrows on 5/29/20.
//

#import "NSDictionary+DictToString.h"

@implementation NSDictionary (DictToString)
-(NSString*) toJSON:(BOOL) prettyPrint {
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:self
                                                       options:(NSJSONWritingOptions)    (prettyPrint ? NSJSONWritingPrettyPrinted : 0)
                                                         error:&error];
    
    if (! jsonData) {
        NSLog(@"%s: error: %@", __func__, error.localizedDescription);
        return @"{}";
    } else {
        return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    }
}

@end
