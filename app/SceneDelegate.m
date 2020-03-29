//
//  SceneDelegate.m
//  iSH
//
//  Created by Theodore Dubois on 10/26/19.
//

#import "SceneDelegate.h"
#import "TerminalViewController.h"
#import "AppGroup.h"

#include "kernel/init.h"





@interface SceneDelegate ()

@property NSString *terminalUUID;

@end

static NSString *const TerminalUUID = @"TerminalUUID";

@implementation SceneDelegate

- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session options:(UISceneConnectionOptions *)connectionOptions {
    NSURL *container = ContainerURL();
    NSURL *alpineRoot = [container URLByAppendingPathComponent:@"roots/alpine"];
    alpineRoot = [alpineRoot URLByAppendingPathComponent:@"data"];
    int err = mount_root(&fakefs, alpineRoot.fileSystemRepresentation);
    if (err < 0) {
        int r = 2;
    }
    
    
    TerminalViewController *vc = (TerminalViewController *) self.window.rootViewController;
    vc.sceneSession = session;
    if (session.stateRestorationActivity == nil) {
        [vc startNewSession];
    } else {
        self.terminalUUID = session.stateRestorationActivity.userInfo[TerminalUUID];
        [vc reconnectSessionFromTerminalUUID:
         [[NSUUID alloc] initWithUUIDString:self.terminalUUID]];
    }
}

- (NSUserActivity *)stateRestorationActivityForScene:(UIScene *)scene {
    NSUserActivity *activity = [[NSUserActivity alloc] initWithActivityType:@"app.ish.scene"];
    TerminalViewController *vc = (TerminalViewController *) self.window.rootViewController;
    self.terminalUUID = vc.sessionTerminalUUID.UUIDString;
    if (self.terminalUUID != nil) {
        [activity addUserInfoEntriesFromDictionary:@{TerminalUUID: self.terminalUUID}];
    }
    return activity;
}

@end
