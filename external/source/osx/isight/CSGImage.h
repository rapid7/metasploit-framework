//
//  CSGImage.h
//  MotionTracker
//
//  Created by Tim Omernick on 3/6/05.
//  Copyright 2005 Tim Omernick. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface CSGImage : NSImage
{    
    NSTimeInterval sampleTime;
}

- (NSTimeInterval)sampleTime;
- (void)setSampleTime:(NSTimeInterval)newSampleTime;

@end
