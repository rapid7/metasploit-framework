//
//  CSGImage.m
//  MotionTracker
//
//  Created by Tim Omernick on 3/6/05.
//  Copyright 2005 Tim Omernick. All rights reserved.
//

#import "CSGImage.h"

@implementation CSGImage

// NSObject subclass

- (NSString *)description;
{
    return [NSString stringWithFormat:@"<%@: %p> (sampleTime=%.4f)", NSStringFromClass([self class]), self, sampleTime];
}

// API

- (NSTimeInterval)sampleTime;
{
    return sampleTime;
}

- (void)setSampleTime:(NSTimeInterval)newSampleTime;
{
    sampleTime = newSampleTime;
}

@end
