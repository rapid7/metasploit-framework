//
//  CSGCamera.h
//  MotionTracker
//
//  Created by Tim Omernick on 3/7/05.
//  Copyright 2005 Tim Omernick. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <QuickTime/QuickTime.h>

@class CSGImage;

/*
	CSGCamera provides a simple way to access the default sequence grabber component (say, an iSight or other DV camera).  To use:
	
	- Instantiate an CSGCamera instance (using the plain old -init method)
	- Set the CSGCamera's delegate using -setDelegate:.  The delegate is the object which will receive -camera:didReceiveFrame: messages.
	- Call -startWithSize: on the CSGCamera instance with a decent size (like 512x384).
	- Call -stop to stop recording.
*/

@interface CSGCamera : NSObject
{
    id delegate;
    SeqGrabComponent component;
    SGChannel channel;
    GWorldPtr gWorld;
    Rect boundsRect;
    ImageSequence decompressionSequence;
    TimeScale timeScale;
    TimeValue lastTime;
	NSTimeInterval startTime;
    NSTimer *frameTimer;
}

- (void)setDelegate:(id)newDelegate;
- (BOOL)startWithSize:(NSSize)frameSize;
- (BOOL)stop;

@end

@interface NSObject (Private)
- (void)camera:(CSGCamera *)aCamera didReceiveFrame:(CSGImage *)aFrame;
@end
