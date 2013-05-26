/***************************************************************************
 *   Copyright (C) 2011 by Dominik Seichter                                *
 *   domseichter@web.de                                                    *
 *                      by Petr Pytelka                                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Library General Public License as       *
 *   published by the Free Software Foundation; either version 2 of the    *
 *   License, or (at your option) any later version.                       *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU Library General Public     *
 *   License along with this program; if not, write to the                 *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#ifndef _PODOFO_SIGN_OUTPUT_DEVICE_H_
#define _PODOFO_SIGN_OUTPUT_DEVICE_H_

#include "../base/PdfOutputDevice.h"
#include "../base/PdfData.h"
#include "../base/PdfString.h"

namespace PoDoFo 
{

/** Signer class
 *
 * Class is used to locate place for signature in the stream.
 * Usage:
 * 1. Locate signature and adjust ByteRange
 * 2. Generate signature
 * 3. Insert new signature
 */
class PODOFO_DOC_API PdfSignOutputDevice :public PdfOutputDevice 
{
    PdfOutputDevice *m_pRealDevice;
    bool m_bDevOwner;
    PdfData *m_pSignatureBeacon;
    size_t m_sBeaconPos;
    bool m_bBeaconFound;
    void Init();
public:
    PdfSignOutputDevice(PdfOutputDevice *pRealDevice);
    PdfSignOutputDevice(const char* pszFilename);
#ifdef WIN32
    PdfSignOutputDevice( const wchar_t* pszFilename );
#endif
    virtual ~PdfSignOutputDevice();

    /** Set string to lookup for 
     * 
     * \param lSignatureSize Total space reserved for signature
     */
    virtual void SetSignatureSize(size_t lSignatureSize);

    /** Get expected size of signature.
     * 
	 * If reserved size if zero no signatures will be added.
     * \return Total space reserved for signature.
     */
	virtual size_t GetSignatureSize()const;

    /** Return signature beacon
     * 
     */
    virtual const PdfData *GetSignatureBeacon()const;

    virtual bool HasSignaturePosition()const;

    /** Modify ByteRange entry according to signature position
     *
     */
    virtual void AdjustByteRange();

    /** Read data for signature
     */
    virtual size_t ReadForSignature(char* pBuffer, size_t lLen);

    /** Embed real signature in the PDF
     */
    virtual void SetSignature(const PdfData &sigData);

    virtual size_t GetLength() const;
    virtual void Print( const char* pszFormat, ... );
    virtual void Write( const char* pBuffer, size_t lLen );
    virtual size_t Read( char* pBuffer, size_t lLen );
    virtual void Seek( size_t offset );
    virtual size_t Tell() const;
    virtual void Flush();
};

}

#endif
