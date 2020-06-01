//
//  NSDictionary+DictToString.h
//  iSH
//
//
// Actually from https://stackoverflow.com/questions/6368867/generate-json-string-from-nsdictionary-in-ios
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN


@interface NSDictionary (DictToString)
-(NSString*) toJSON:(BOOL) prettyPrint;
@end

NS_ASSUME_NONNULL_END
