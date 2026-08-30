//
//  CSGCamera.m
//  MotionTracker
//
//  Created by Tim Omernick on 3/7/05.
//  Copyright 2005 Tim Omernick. All rights reserved.
//

// Portions of this file were inspired by Apple Computer, Inc.'s Cocoa SGDataProc example, which can be found here:
// <http://developer.apple.com/samplecode/Cocoa_-_SGDataProc/Cocoa_-_SGDataProc.html>
// Also, I'd like to thank Chris Meyer for his excellent -imageFromGWorld: method, which he gave me permission to use for this framework.

#import "CSGCamera.h"

#import "CSGImage.h"

@interface CSGCamera (Private)
- (void)_sequenceGrabberIdle;
- (BOOL)_setupDecompression;
- (void)_didUpdate;
- (CSGImage *)_imageFromGWorld:(GWorldPtr)gworld;
@end

@interface CSGCamera (SequenceGrabber)
pascal OSErr CSGCameraSGDataProc(SGChannel channel, Ptr data, long dataLength, long *offset, long channelRefCon, TimeValue time, short writeType, long refCon);
@end

@implementation CSGCamera

// Init and dealloc

- (void)dealloc;
{
	[self stop];
	
	[delegate release];
	
	[super dealloc];
}

// API

- (void)setDelegate:(id)newDelegate;
{
    if (delegate == newDelegate)
        return;
        
    [delegate release];
    delegate = [newDelegate retain];
}

- (BOOL)startWithSize:(NSSize)frameSize;
{
    OSErr theErr;
    
    timeScale = 0;
    lastTime = 0;
    
    // Initialize movie toolbox
    theErr = EnterMovies();
    if (theErr != noErr) {
        NSLog(@"EnterMovies() returned %ld", theErr);
        return NO;
    }
    
    // Open default sequence grabber component
    component = OpenDefaultComponent(SeqGrabComponentType, 0);
    if (!component) {
        NSLog(@"Could not open sequence grabber component.");
        return NO;
    }
    
    // Initialize sequence grabber component
    theErr = SGInitialize(component);
    if (theErr != noErr) {
        NSLog(@"SGInitialize() returned %ld", theErr);
        return NO;
    }
    
    // Don't make movie
    theErr = SGSetDataRef(component, 0, 0, seqGrabDontMakeMovie);
    if (theErr != noErr) {
        NSLog(@"SGSetDataRef() returned %ld", theErr);
        return NO;
    }
    
    // Create sequence grabber video channel
    theErr = SGNewChannel(component, VideoMediaType, &channel);
    if (theErr != noErr) {
        NSLog(@"SGNewChannel() returned %ld", theErr);
        return NO;
    }
    
    // Set the grabber's bounds
    boundsRect.top = 0;
    boundsRect.left = 0;
    boundsRect.bottom = frameSize.height;
    boundsRect.right = frameSize.width;
	
//    NSLog(@"boundsRect=(%d, %d, %d, %d)", boundsRect.top, boundsRect.left, boundsRect.bottom, boundsRect.right);
    
    theErr = SGSetChannelBounds(component, &boundsRect);
    
    // Create the GWorld
    theErr = QTNewGWorld(&gWorld, k32ARGBPixelFormat, &boundsRect, 0, NULL, 0);
    if (theErr != noErr) {
        NSLog(@"QTNewGWorld() returned %ld", theErr);
        return NO;
    }
    
    // Lock the pixmap
    if (!LockPixels(GetPortPixMap(gWorld))) {
        NSLog(@"Could not lock pixels.");
        return NO;
    }
    
    // Set GWorld
    theErr = SGSetGWorld(component, gWorld, GetMainDevice());
    if (theErr != noErr) {
        NSLog(@"SGSetGWorld() returned %ld", theErr);
        return NO;
    }
    
    // Set the channel's bounds
    theErr = SGSetChannelBounds(channel, &boundsRect);
    if (theErr != noErr) {
        NSLog(@"SGSetChannelBounds(2) returned %ld", theErr);
        return NO;
    }
    
    // Set the channel usage to record
    theErr = SGSetChannelUsage(channel, seqGrabRecord);
    if (theErr != noErr) {
        NSLog(@"SGSetChannelUsage() returned %ld", theErr);
        return NO;
    }
    
    // Set data proc
    theErr = SGSetDataProc(component, NewSGDataUPP(&CSGCameraSGDataProc), (long)self);
    if (theErr != noErr) {
        NSLog(@"SGSetDataProc() returned %ld", theErr);
        return NO;
    }
    
    // Prepare
    theErr = SGPrepare(component, false, true);
    if (theErr != noErr) {
        NSLog(@"SGPrepare() returned %ld", theErr);
        return NO;
    }
    
    // Start recording
    theErr = SGStartRecord(component);
    if (theErr != noErr) {
        NSLog(@"SGStartRecord() returned %ld", theErr);
        return NO;
    }

	startTime = [NSDate timeIntervalSinceReferenceDate];
	
    // Set up decompression sequence (camera -> GWorld)
    [self _setupDecompression];
    
    // Start frame timer
    frameTimer = [[NSTimer scheduledTimerWithTimeInterval:0.0 target:self selector:@selector(_sequenceGrabberIdle) userInfo:nil repeats:YES] retain];
        
    [self retain]; // Matches autorelease in -stop
    
    return YES;
}

- (BOOL)stop;
{    
    // Stop frame timer
	if (frameTimer) {
		[frameTimer invalidate];
		[frameTimer release];
		frameTimer = nil;
	}
    
    // Stop recording
	if (component)
		SGStop(component);
    
    ComponentResult theErr;

    // End decompression sequence
	if (decompressionSequence) {
		theErr = CDSequenceEnd(decompressionSequence);
		if (theErr != noErr) {
			NSLog(@"CDSequenceEnd() returned %ld", theErr);
		}
		decompressionSequence = 0;
	}
    
    // Close sequence grabber component
	if (component) {
		theErr = CloseComponent(component);
		if (theErr != noErr) {
			NSLog(@"CloseComponent() returned %ld", theErr);
		}
		component = NULL;
	}
    
    // Dispose of GWorld
	if (gWorld) {
		DisposeGWorld(gWorld);
		gWorld = NULL;
	}
    
    [self autorelease]; // Matches retain in -start
    
    return YES;
}

@end

@implementation CSGCamera (Private)

- (void)_sequenceGrabberIdle;
{
    OSErr theErr;
    
    theErr = SGIdle(component);
    if (theErr != noErr) {
        NSLog(@"SGIdle returned %ld", theErr);
        return;
    }
}

- (BOOL)_setupDecompression;
{
    ComponentResult theErr;
    
    ImageDescriptionHandle imageDesc = (ImageDescriptionHandle)NewHandle(0);
    theErr = SGGetChannelSampleDescription(channel, (Handle)imageDesc);
    if (theErr != noErr) {
        NSLog(@"SGGetChannelSampleDescription() returned %ld", theErr);
        return NO;
    }
    
    Rect sourceRect;
    sourceRect.top = 0;
    sourceRect.left = 0;
    sourceRect.right = (**imageDesc).width;
    sourceRect.bottom = (**imageDesc).height;
    
    MatrixRecord scaleMatrix;
    RectMatrix(&scaleMatrix, &sourceRect, &boundsRect);
    
    theErr = DecompressSequenceBegin(&decompressionSequence, imageDesc, gWorld, NULL, NULL, &scaleMatrix, srcCopy, NULL, 0, codecNormalQuality, bestSpeedCodec);
    if (theErr != noErr) {
        NSLog(@"DecompressionSequenceBegin() returned %ld", theErr);
        return NO;
    }
    
    DisposeHandle((Handle)imageDesc);
	
	return YES;
}

- (void)_didUpdate;
{
    if ([delegate respondsToSelector:@selector(camera:didReceiveFrame:)]) {
        CSGImage *frameImage = [self _imageFromGWorld:gWorld];
        if (frameImage) {
            [frameImage setSampleTime:startTime + ((double)lastTime / (double)timeScale)];
            [delegate camera:self didReceiveFrame:frameImage];
        }
    }
}

// Thanks to Chris Meyer from http://www.cocoadev.com/
- (CSGImage *)_imageFromGWorld:(GWorldPtr)gworld;
{
    NSParameterAssert( gworld != NULL );

    PixMapHandle pixMapHandle = GetGWorldPixMap( gworld );
    if ( LockPixels( pixMapHandle ) )
    {
        Rect portRect;
        GetPortBounds( gworld, &portRect );
        int pixels_wide = (portRect.right - portRect.left);
        int pixels_high = (portRect.bottom - portRect.top);

        int bps = 8;
        int spp = 4;
        BOOL has_alpha = YES;

        NSBitmapImageRep *frameBitmap = [[[NSBitmapImageRep alloc]
            initWithBitmapDataPlanes:NULL
                          pixelsWide:pixels_wide
                          pixelsHigh:pixels_high
                       bitsPerSample:bps
                     samplesPerPixel:spp
                            hasAlpha:has_alpha
                            isPlanar:NO
                      colorSpaceName:NSDeviceRGBColorSpace
                         bytesPerRow:0
                        bitsPerPixel:0] autorelease];
        
        CGColorSpaceRef dst_colorspaceref = CGColorSpaceCreateDeviceRGB();

        CGImageAlphaInfo dst_alphainfo = has_alpha ? kCGImageAlphaPremultipliedLast : kCGImageAlphaNone;

        CGContextRef dst_contextref = CGBitmapContextCreate( [frameBitmap bitmapData],
                                                             pixels_wide,
                                                             pixels_high,
                                                             bps,
                                                             [frameBitmap bytesPerRow],
                                                             dst_colorspaceref,
                                                             dst_alphainfo );

        void *pixBaseAddr = GetPixBaseAddr(pixMapHandle);

        long pixmapRowBytes = GetPixRowBytes(pixMapHandle);

        CGDataProviderRef dataproviderref = CGDataProviderCreateWithData( NULL, pixBaseAddr, pixmapRowBytes * pixels_high, NULL );

        int src_bps = 8;
        int src_spp = 4;
        BOOL src_has_alpha = YES;

        CGColorSpaceRef src_colorspaceref = CGColorSpaceCreateDeviceRGB();

        CGImageAlphaInfo src_alphainfo = src_has_alpha ? kCGImageAlphaPremultipliedFirst : kCGImageAlphaNone;

        CGImageRef src_imageref = CGImageCreate( pixels_wide,
                                                 pixels_high,
                                                 src_bps,
                                                 src_bps * src_spp,
                                                 pixmapRowBytes,
                                                 src_colorspaceref,
                                                 src_alphainfo,
                                                 dataproviderref,
                                                 NULL,
                                                 NO, // shouldInterpolate
                                                 kCGRenderingIntentDefault );

        CGRect rect = CGRectMake( 0, 0, pixels_wide, pixels_high );

        CGContextDrawImage( dst_contextref, rect, src_imageref );

        CGImageRelease( src_imageref );
        CGColorSpaceRelease( src_colorspaceref );
        CGDataProviderRelease( dataproviderref );
        CGContextRelease( dst_contextref );
        CGColorSpaceRelease( dst_colorspaceref );

        UnlockPixels( pixMapHandle );

        CSGImage *image = [[CSGImage alloc] initWithSize:NSMakeSize(pixels_wide, pixels_high)];
        [image addRepresentation:frameBitmap];
        
        return [image autorelease];
    }
    
    return NULL;
}

@end

@implementation CSGCamera (SequenceGrabber)

pascal OSErr CSGCameraSGDataProc(SGChannel channel, Ptr data, long dataLength, long *offset, long channelRefCon, TimeValue time, short writeType, long refCon)
{
    CSGCamera *camera = (CSGCamera *)refCon;
    ComponentResult theErr;
    
    if (camera->timeScale == 0) {
        theErr = SGGetChannelTimeScale(camera->channel, &camera->timeScale);
        if (theErr != noErr) {
            NSLog(@"SGGetChannelTimeScale() returned %ld", theErr);
            return theErr;
        }
    }
    
    if (camera->gWorld) {
        CodecFlags ignore;
        theErr = DecompressSequenceFrameS(camera->decompressionSequence, data, dataLength, 0, &ignore, NULL);
        if (theErr != noErr) {
            NSLog(@"DecompressSequenceFrameS() returned %ld", theErr);
            return theErr;
        }
    }
    
    camera->lastTime = time;
    
    [camera _didUpdate];
    
    return noErr;
}

@end
